import os
import pathlib
import json
import smtplib
from email.mime.text import MIMEText
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()

# Directory to publish reports so they are accessible under /static/reports/
REPORTS_DIR = pathlib.Path(__file__).resolve().parents[2] / 'frontend' / 'static' / 'reports'
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class UploadReportPayload(BaseModel):
    filename: str
    content: str


class SendReportPayload(BaseModel):
    channel: str
    target: str
    report_url: str
    message: str = ''


@router.post('/api/v1/report/upload')
def upload_report(payload: UploadReportPayload):
    # sanitize filename
    name = os.path.basename(payload.filename)
    if not name.lower().endswith('.html'):
        name = name + '.html'
    dest = REPORTS_DIR / name
    try:
        with open(dest, 'w', encoding='utf-8') as fh:
            fh.write(payload.content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Failed to write report: {e}')
    return {'url': f'/static/reports/{name}', 'path': str(dest)}


@router.post('/api/v1/integrations/send_report', operation_id='integrations_send_report')
def send_report(payload: SendReportPayload, request: Request):
    # Basic demo integrations: if target is a URL, POST JSON {text: message + report_url}
    target = payload.target or ''
    channel = (payload.channel or '').lower()
    report_url = payload.report_url
    # Resolve absolute URL if request has base
    base = str(request.base_url).rstrip('/')
    if report_url.startswith('/'):
        report_url = base + report_url

    # If target looks like a webhook URL, POST to it
    if target.startswith('http://') or target.startswith('https://'):
        from src.security.configured_targets import configured_webhook
        import httpx
        try:
            destination = configured_webhook(target)
        except ValueError:
            raise HTTPException(status_code=400, detail='Webhook destination is not approved') from None
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False, trust_env=False) as client:
                response = client.post(destination, json={'text': (payload.message or '') + '\n' + report_url})
            if not 200 <= response.status_code < 300:
                raise HTTPException(status_code=502, detail='Webhook delivery failed')
            return {'status': 'sent', 'via': 'webhook', 'code': response.status_code}
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail='Webhook delivery failed') from None

    # If channel is email, attempt SMTP if configured, else return mailto link
    if channel in ('email', 'mail') or ('@' in target and not target.startswith('+')):
        smtp_host = os.environ.get('SMTP_HOST')
        smtp_port = int(os.environ.get('SMTP_PORT', '0') or 0)
        smtp_user = os.environ.get('SMTP_USER')
        smtp_pass = os.environ.get('SMTP_PASS')
        subject = payload.message or 'Security Analysis Report'
        body = f'{subject}\n\nReport: {report_url}\n'
        if smtp_host and smtp_port:
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = smtp_user or f'no-reply@{request.client.host}'
            msg['To'] = target
            try:
                s = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                s.starttls()
                if smtp_user and smtp_pass:
                    s.login(smtp_user, smtp_pass)
                s.sendmail(msg['From'], [target], msg.as_string())
                s.quit()
                return {'status':'sent', 'via':'smtp'}
            except Exception as e:
                raise HTTPException(status_code=502, detail=f'SMTP send failed: {e}')
        else:
            # return a mailto fallback
            mailto = f'mailto:{target}?subject={subject}&body={report_url}'
            return {'status':'pending', 'via':'mailto', 'mailto': mailto}

    # For phone/whatsapp we expect a webhook target; otherwise return unsupported
    raise HTTPException(status_code=400, detail='Unsupported integration: provide a webhook URL or an email address')
