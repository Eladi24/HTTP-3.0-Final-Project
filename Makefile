startContainers:
	@echo "Starting aioquic, aioquic-client, and quicforge containers..."
	docker start aioquic-container
	docker start client-container
	docker start quicforge-container

stopContainers:
	@echo "Stopping all containers..."
	docker stop $$(docker ps -q)

restartContainers:
	@echo "Restarting all containers..."
	docker restart $$(docker ps -q)

execAioquic:
	@echo "Executing aioquic container..."
	docker exec -it aioquic-container bash

execClient:
	@echo "Executing client container..."
	docker exec -it client-container /bin/bash

execQuicforge:
	@echo "Executing quicforge container..."
	docker exec -it quicforge-container /bin/bash

containersStatus:
	@echo "Checking status of all containers..."
	docker ps -a
.PHONY: startContainers stopContainers restartContainers execAioquic execClient execQuicforge containersStatus