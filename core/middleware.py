# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Headers that tell the browser what a Loona page may do."""

# Scripts only from Loona's own files: an injected <script> or onclick= does
# not run.  'unsafe-eval' stays because Alpine and htmx evaluate their
# attributes; styles stay inline-friendly because the templates use style=.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
])
# Nothing in Loona needs these.
PERMISSIONS_POLICY = ", ".join(f"{feature}=()" for feature in (
    "accelerometer", "camera", "geolocation", "gyroscope", "magnetometer", "microphone",
    "payment", "usb", "serial", "hid", "bluetooth", "display-capture", "browsing-topics",
))


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        return response
