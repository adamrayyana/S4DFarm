import logging
from typing import Iterable

import requests

from models import FlagStatus, SubmitResult

logger = logging.getLogger(__name__)

TIMEOUT = 5

REJECTED_HINTS = (
    'invalid',
    'already submitted',
    'duplicate',
    'old',
    'expired',
    'own flag',
    'your own',
)

RETRY_HINTS = (
    'rate limit',
    'wait',
    'later',
    'timeout',
    'try again',
    'game not started',
    'not started',
)


def submit_flags(flags: Iterable, config: dict):
    url = config['SYSTEM_URL']
    token = config['SYSTEM_TOKEN']

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }

    for flag in flags:
        try:
            response = requests.post(
                url,
                headers=headers,
                json={'flag': flag.flag},
                timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            message = str(exc)
            logger.warning('Flag %s submission failed: %s', flag.flag, message)
            yield SubmitResult(flag.flag, FlagStatus.QUEUED, message)
            continue

        message = response.text.strip()
        payload = None

        try:
            payload = response.json()
        except ValueError:
            pass

        if isinstance(payload, dict):
            message = str(
                payload.get('message')
                or payload.get('detail')
                or payload.get('status')
                or message
            )

        normalized = message.lower()

        if response.ok or 'accept' in normalized:
            status = FlagStatus.ACCEPTED
        elif any(hint in normalized for hint in REJECTED_HINTS):
            status = FlagStatus.REJECTED
        elif response.status_code >= 500 or any(hint in normalized for hint in RETRY_HINTS):
            status = FlagStatus.QUEUED
        else:
            status = FlagStatus.REJECTED

        yield SubmitResult(flag.flag, status, message or response.reason)
