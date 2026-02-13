TARGET=evilginx
PACKAGES=core database log parser
INSTALL_DIR=/opt/evilginx

.PHONY: all build clean install setup

all: build

build:
	@mkdir -p ./build
	@go build -o ./build/$(TARGET) -mod=vendor main.go
	@echo "Built: ./build/$(TARGET)"

clean:
	@go clean
	@rm -f ./build/$(TARGET)

install: build
	@mkdir -p $(INSTALL_DIR)/phishlets $(INSTALL_DIR)/redirectors
	@cp -f ./build/$(TARGET) $(INSTALL_DIR)/$(TARGET)
	@chmod +x $(INSTALL_DIR)/$(TARGET)
	@cp -r ./phishlets/* $(INSTALL_DIR)/phishlets/ 2>/dev/null || true
	@cp -r ./redirectors/* $(INSTALL_DIR)/redirectors/ 2>/dev/null || true
	@ln -sf $(INSTALL_DIR)/$(TARGET) /usr/local/bin/$(TARGET)
	@echo "Installed to $(INSTALL_DIR) and linked to /usr/local/bin/$(TARGET)"

setup:
	@chmod +x ./setup-debian.sh
	@sudo ./setup-debian.sh
