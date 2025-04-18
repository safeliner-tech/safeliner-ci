from alpine/curl:8.12.1 as build

RUN curl -v -o /usr/bin/safeliner-dfg-cli-0.0.3 https://devplatform-security-safeliner.t-static.ru/dfg-cli/0.0.3/linux/amd64/safeliner-dfg-cli

from python:3.12.9-slim

RUN apt-get update \
&& apt-get install -y --no-install-recommends git \
&& apt-get purge -y --auto-remove \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY src/integration.py /usr/bin/integration.py
COPY --from=build /usr/bin/safeliner-dfg-cli-0.0.3 /usr/bin/safeliner-dfg-cli-0.0.3
RUN ln -s /usr/bin/safeliner-dfg-cli-0.0.3 /usr/bin/safeliner-dfg-cli
RUN chmod +x /usr/bin/safeliner-dfg-cli-0.0.3 /usr/bin/safeliner-dfg-cli

CMD [ "/bin/sh" ]