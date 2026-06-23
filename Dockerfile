# Copyright (c) 2026 Rick Bohm
# Summit Cyber Group, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM python:3.12-slim

# Scanning toolchain. nmap (service/version + scripts), masscan (fast sweep),
# fping (icmp liveness), plus libs nmap's OS/version detection wants.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        fping \
        iproute2 \
        iputils-ping \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# data/ holds the sqlite db + raw nmap xml. Mounted as a volume so it survives
# rebuilds and is the single thing you back up.
RUN mkdir -p /app/data

ENV D1_HOST=127.0.0.1 \
    D1_PORT=8040

EXPOSE 8040

# Bind to D1_HOST (default 127.0.0.1). With host networking this keeps the UI
# local-only; set D1_HOST=0.0.0.0 in compose if you ever need LAN access.
CMD ["sh", "-c", "python -m uvicorn app.main:app --host ${D1_HOST} --port ${D1_PORT}"]
