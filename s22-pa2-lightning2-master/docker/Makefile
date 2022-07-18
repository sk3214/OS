COMPOSE = docker-compose

.PHONY: phase3-tests phase3-wait-exec-tests phase3-create-tests phase3-open-tests phase3-close-tests phase3-halt-test phase3-read-tests phase3-write-tests

echo:
	$(COMPOSE) run --rm emulator /bin/bash -c 'echo Hello, World'
 
clean:
	$(COMPOSE) run --rm emulator make clean

build-userprog:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog && make"

phase1-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "python pa2_student_test/arg_test.py"

phase2-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/args-none.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/args-single.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/args-multiple.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/args-many.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/args-dbl-space.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exit.result"

phase3-wait-exec-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/wait-simple.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/wait-twice.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/wait-killed.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/wait-bad-pid.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exec-arg.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exec-bad-ptr.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exec-missing.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exec-multiple.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/exec-once.result"

phase3-tests: phase3-wait-exec-tests phase3-create-tests phase3-open-tests phase3-close-tests phase3-halt-test phase3-read-tests phase3-write-tests

phase3-halt-test: 
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/halt.result"

phase3-create-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-normal.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-empty.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-bound.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-exists.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-bad-ptr.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-long.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/create-null.result"

phase3-open-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-normal.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-empty.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-twice.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-null.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-missing.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-boundary.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/open-bad-ptr.result"

phase3-close-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/close-normal.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/close-twice.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/close-stdout.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/close-stdin.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/close-bad-fd.result"

phase3-rox-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/rox-child.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/rox-multichild.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/rox-simple.result"

phase3-write-tests:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-normal.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-boundary.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-zero.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-bad-fd.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-bad-ptr.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/write-stdin.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/bad-write.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/bad-write2.result"
phase3-read-tests:

	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-normal.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-zero.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-bad-fd.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-stdout.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-boundary.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/userprog/build && make tests/userprog/read-bad-ptr.result"
