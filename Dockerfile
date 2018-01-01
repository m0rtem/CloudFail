FROM debian:sid

ENV LANG C.UTF-8
ENV USER root
ENV HOME /cloudfail
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update

RUN apt-get install -yq python3-pip

COPY . $HOME

WORKDIR $HOME

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "cloudfail.py"]
