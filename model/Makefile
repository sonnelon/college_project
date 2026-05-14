REQUIREMENTS_PATH = ./requirements.txt
MAIN_FILE = ./main.py
VENV_DIR = .venv
PY = python
PKG = pip
ACTIVATE_SCRIPT_PATH = ${VENV_DIR}/bin/activate

.PHONY: install all activate_venv

all: install

activate_venv:
	@source ${ACTIVATE_SCRIPT_PATH}

install: 
	${PY} -m venv ${VENV_DIR}
	@activate_venv && ${PKG} install -r ${REQUIREMENTS_PATH}
