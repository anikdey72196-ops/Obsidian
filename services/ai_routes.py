import logging
logger = logging.getLogger(__name__)
import os
import json
import time
import requests
from datetime import date, timedelta
from flask import Blueprint, request, jsonify, session, Response, stream_with_context

from services.ai_providers import call_groq, call_ollama, call_llm_single, GROQ_API_KEY, GROQ_MODEL, OLLAMA_BASE_URL, OLLAMA_MODEL
from services.ai_analytics import check_rate_limit, get_expense_summary, generate_fallback_tips, build_system_prompt

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')


@ai_bp.route('/chat', methods=['POST'])
def chat():
    """Handle AI chat messages with streaming response (Groq Cloud API + Ollama fallback)."""
    if 'user_id' not in session:
        return jsonify({"error": "Please login first"}), 401

    user_id = session['user_id']

    if check_rate_limit(user_id):
        return jsonify({"error": "Please wait a few seconds before sending another message."}), 429

    data = request.get_json()
    if not data or not data.get('message'):
        return jsonify({"error": "Message is required"}), 400

    user_message = data['message'].strip()
    if len(user_message) > 500:
        return jsonify({"error": "Message too long (max 500 characters)"}), 400

    try:
        summary_text, _ = get_expense_summary(user_id)

        messages = [
            {"role": "system", "content": build_system_prompt(summary_text)},
            {"role": "user", "content": user_message}
        ]

        current_groq_key = os.environ.get('GROQ_API_KEY', GROQ_API_KEY).strip()

        def generate():
            try:
                if current_groq_key:
                    resp = call_groq(messages, stream=True, max_tokens=300, timeout=30)
                    for line in resp.iter_lines():
                        if line:
                            decoded = line.decode('utf-8')
                            if decoded.startswith('data: '):
                                raw_data = decoded[6:].strip()
                                if raw_data == '[DONE]':
                                    yield f"data: {json.dumps({'done': True})}\n\n"
                                    break
                                try:
                                    chunk = json.loads(raw_data)
                                    delta = chunk.get('choices', [{}])[0].get('delta', {})
                                    content = delta.get('content', '')
                                    if content:
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                                except Exception:
                                    pass
                else:
                    resp = call_ollama(messages, stream=True, num_predict=256, timeout=15)
                    for line in resp.iter_lines():
                        if line:
                            chunk = json.loads(line)
                            msg = chunk.get('message', {})
                            content = msg.get('content', '')
                            if content:
                                yield f"data: {json.dumps({'content': content})}\n\n"
                            if chunk.get('done', False):
                                yield f"data: {json.dumps({'done': True})}\n\n"
                                break

            except requests.exceptions.Timeout:
                yield f"data: {json.dumps({'error': 'The AI model took too long to respond (timeout). Please try sending your message again!'})}\n\n"
            except requests.exceptions.ConnectionError:
                yield f"data: {json.dumps({'error': 'Cannot connect to AI service. Please check your GROQ_API_KEY or local Ollama status.'})}\n\n"
            except Exception as e:
                logger.exception('AI generation error')
                yield f"data: {json.dumps({'error': 'AI service error. Please try again.'})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
            }
        )

    except Exception as e:
        logger.exception('AI service error')
        return jsonify({'error': 'AI service temporarily unavailable.'}), 500


@ai_bp.route('/insights', methods=['GET'])
def insights():
    """Generate AI-powered spending insights (Groq Cloud AI + fast fallback)."""
    if 'user_id' not in session:
        return jsonify({"error": "Please login first"}), 401

    user_id = session['user_id']

    cache_key = f"ai_insights_{user_id}"
    cached = session.get(cache_key)
    force_refresh = request.args.get('refresh') == 'true'

    if cached and not force_refresh:
        cached_time = session.get(f"{cache_key}_time", 0)
        if time.time() - cached_time < 1800:
            return jsonify(cached)

    try:
        summary_text, stats = get_expense_summary(user_id)

        if stats['num_expenses_this_month'] == 0:
            result = {
                'predicted_total': 0,
                'budget_status': 'neutral',
                'tips': ["Start tracking your expenses to get AI-powered insights! 📊"],
                'trend': 'stable',
                'summary': 'No expenses recorded this month yet. Add expenses to see predictions!'
            }
            return jsonify(result)

        today = date.today()
        days_in_month = (today.replace(month=today.month % 12 + 1, day=1) - timedelta(days=1)).day if today.month < 12 else 31
        predicted_total = stats['daily_avg'] * days_in_month

        if stats['last_month_total'] > 0:
            if predicted_total > stats['last_month_total'] * 1.2:
                budget_status = 'danger'
            elif predicted_total > stats['last_month_total']:
                budget_status = 'warning'
            else:
                budget_status = 'good'
        else:
            budget_status = 'neutral'

        if stats['last_month_total'] > 0:
            change_pct = ((stats['this_month_total'] - stats['last_month_total']) / stats['last_month_total']) * 100
            if change_pct > 10:
                trend = 'up'
            elif change_pct < -10:
                trend = 'down'
            else:
                trend = 'stable'
        else:
            trend = 'stable'

        tips = None
        try:
            tip_messages = [
                {"role": "system", "content": f"Based on spending: {summary_text}\nOutput ONLY a JSON array of 3 short financial tips."},
                {"role": "user", "content": "Give me 3 short saving tips as a JSON array of 3 strings."}
            ]
            tip_response = call_llm_single(tip_messages, max_tokens=150, timeout=15)
            tip_response = tip_response.strip()
            if tip_response.startswith('```'):
                tip_response = tip_response.split('\n', 1)[1] if '\n' in tip_response else tip_response
                tip_response = tip_response.rsplit('```', 1)[0]
                tip_response = tip_response.strip()
            parsed_tips = json.loads(tip_response)
            if isinstance(parsed_tips, list) and len(parsed_tips) > 0:
                tips = [str(t) for t in parsed_tips[:3]]
        except Exception:
            tips = generate_fallback_tips(stats)

        if not tips:
            tips = generate_fallback_tips(stats)

        result = {
            'predicted_total': round(predicted_total, 2),
            'budget_status': budget_status,
            'tips': tips,
            'trend': trend,
            'this_month_total': round(stats['this_month_total'], 2),
            'last_month_total': round(stats['last_month_total'], 2),
            'daily_avg': round(stats['daily_avg'], 2),
            'days_remaining': max(days_in_month - stats['days_elapsed'], 0),
            'summary': f"At your current pace of ₹{stats['daily_avg']:,.0f}/day, you're projected to spend ₹{predicted_total:,.0f} this month."
        }

        session[cache_key] = result
        session[f"{cache_key}_time"] = time.time()

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'predicted_total': 0,
            'budget_status': 'neutral',
            'tips': ['Keep tracking expenses for AI insights!'],
            'trend': 'stable',
            'summary': 'AI insights loading error.'
        })


@ai_bp.route('/health', methods=['GET'])
def health():
    """Check if AI provider (Groq or Ollama) is reachable."""
    current_groq_key = os.environ.get('GROQ_API_KEY', GROQ_API_KEY).strip()
    if current_groq_key:
        return jsonify({
            "status": "connected",
            "provider": "Groq Cloud AI",
            "model": GROQ_MODEL
        })

    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        resp.raise_for_status()
        models = resp.json().get('models', [])
        model_names = [m.get('name', '') for m in models]
        return jsonify({
            "status": "connected",
            "provider": "Local Ollama",
            "models": model_names,
            "active_model": OLLAMA_MODEL
        })
    except Exception:
        return jsonify({
            "status": "disconnected",
            "provider": "None",
            "error": "No GROQ_API_KEY set and local Ollama is un-reachable"
        }), 503
