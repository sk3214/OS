COMPOSE = docker-compose

echo:
	$(COMPOSE) run --rm emulator /bin/bash -c 'echo Hello, World'
 
clean:
	$(COMPOSE) run --rm emulator make clean

build-threads:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads && sed -i 's/--bochs/--qemu/' Make.vars && make"

test-pa1-phase1:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-change.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-preempt.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-fifo.result"

test-pa1-phase2:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-single.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-multiple.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-simultaneous.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-priority.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-zero.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/alarm-negative.result"

test-pa1-phase3-mlfqs:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-load-1.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-load-60.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-load-avg.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-recent-1.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-nice-2.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-nice-10.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-fair-2.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-fair-20.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/mlfqs-block.result"

test-pa1-phase3-donation:
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-one.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-multiple.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-multiple2.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-nest.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-sema.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-lower.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-sema.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-condvar.result"
	$(COMPOSE) run --rm emulator /bin/bash -c "cd src/threads/build && make tests/threads/priority-donate-chain.result"