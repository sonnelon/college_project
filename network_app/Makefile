ZEEK_FILES = quic.log reporter.log ssl.log packet_filter.log conn.log dns.log
PY = python
MAIN_FILE = main.py
INTERFACE = wlan0
ZEEK_SCRIPT = script.zeek
PY_FLAGS = ${MAIN_FILE} -i ${INTERFACE} -z ${ZEEK_SCRIPT}
REQ_PATH = ./requirements.txt
VENV_FLAGS = -m venv
VENV_NAME = .venv
ACTIVATE_PATH = ${VENV_NAME}/bin/activate
PIP_FLAGS = -r ${REQ_PATH}

.PHONY: all clear_zeek install run activate_venv

all:
	@install
	@activate_venv && @run

run:
	${PY} ${PY_FLAGS}

activate_venv:
	${PY} ${VENV_FLAGS} ${VENV_NAME}

install:
	pip install ${PIP_FLAGS}

clear_zeek:
	rm -rf ${ZEEK_FILES}
