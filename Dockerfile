from alpine/curl:8.12.1 as build

RUN curl -v --trace -o /usr/bin/safeliner-dfg-cli-0.0.3 https://devplatform-security-safeliner.t-static.ru/dfg-cli/0.0.3/linux/amd64/safeliner-dfg-cli

from python:3.12.9-slim

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY src/integration.py /usr/bin/integration.py
COPY --from=build /usr/bin/safeliner-dfg-cli-0.0.3 /usr/bin/safeliner-dfg-cli-0.0.3

CMD [ "/bin/sh" ]