FROM python:3.9.16-alpine3.17
ENV LANG C.UTF-8
ENV HOME /cloudfail

COPY . $HOME

WORKDIR $HOME

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "cloudfail.py"]
