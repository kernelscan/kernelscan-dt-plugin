# Build the KernelScan Dependency-Track analyzer plugin.
#
# The DT plugin API is not published to Maven Central, so the compile classpath
# is extracted from the official apiserver image. The plugin API changes between
# DT minors, so one JAR is built per supported minor from the same source:
# src/main/java is shared, src/compat/<flavour>/java adapts the factory's
# init() to that minor's API. Everything runs in containers; the only local
# requirement is Docker.
#
#   make all-dt                     build + test every supported DT minor
#   make build DT_VERSION=5.0.5     one minor (libs are fetched on demand)

# Supported DT releases (latest patch per minor). Patch releases within a minor
# only add API, so a JAR built here loads on every patch of its minor.
DT_VERSIONS := 5.0.5 5.1.2 5.2.1
DT_VERSION  ?= 5.2.1

# Plugin-API flavour per DT minor (see AbstractKernelScanVulnAnalyzerFactory).
COMPAT_5.0 := service-registry
COMPAT_5.1 := service-registry
COMPAT_5.2 := extension-context

DT_MINOR := $(word 1,$(subst ., ,$(DT_VERSION))).$(word 2,$(subst ., ,$(DT_VERSION)))
COMPAT   := $(COMPAT_$(DT_MINOR))
DT_IMAGE ?= ghcr.io/dependencytrack/apiserver:$(DT_VERSION)
JDK_IMAGE ?= eclipse-temurin:25-jdk
JUNIT_URL ?= https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.11.3/junit-platform-console-standalone-1.11.3.jar
VERSION  := $(shell cat VERSION)
LIBS     := libs/$(DT_VERSION)
OUT      := build/dt$(DT_MINOR)
JAR      := kernelscan-dt-plugin.jar
SOURCES  := src/main/java src/compat/$(COMPAT)/java

# Compile-classpath jars, globbed from the image's lib/.
LIB_PATTERNS := plugin-api- vuln-analysis-api- cyclonedx-proto- \
                protobuf-java- slf4j-api- jackson-core- jackson-databind- \
                jackson-annotations- jspecify-

.PHONY: all all-dt libs build test clean deploy version dt-versions check-dt

all: build

version:
	@echo "plugin $(VERSION), target Dependency-Track $(DT_VERSION) ($(COMPAT))"

dt-versions:
	@echo $(DT_VERSIONS)

check-dt:
	@test -n "$(COMPAT)" || { echo "unsupported Dependency-Track minor $(DT_MINOR) (supported: $(DT_VERSIONS))"; exit 1; }

$(LIBS):
	rm -rf $(LIBS).tmp && mkdir -p $(LIBS).tmp
	docker rm -f ksdtp-extract >/dev/null 2>&1 || true
	docker create --name ksdtp-extract $(DT_IMAGE) >/dev/null
	docker cp ksdtp-extract:/opt/owasp/dependency-track/lib $(LIBS).tmp/all
	docker rm ksdtp-extract >/dev/null
	@for p in $(LIB_PATTERNS); do \
	  cp $(LIBS).tmp/all/$$p*.jar $(LIBS).tmp/ 2>/dev/null || echo "WARN: no jar matching $$p*"; \
	done
	rm -rf $(LIBS).tmp/all && mv $(LIBS).tmp $(LIBS)
	@ls $(LIBS)

libs: check-dt $(LIBS)

build: check-dt $(LIBS)
	rm -rf $(OUT) && mkdir -p $(OUT)/classes
	printf 'Implementation-Title: kernelscan-dt-plugin\nImplementation-Version: %s\nX-DependencyTrack-Version: %s\nX-DependencyTrack-Minor: %s\n' \
	  "$(VERSION)" "$(DT_VERSION)" "$(DT_MINOR)" > $(OUT)/MANIFEST.MF
	docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) sh -c '\
	  javac -Xlint:all -Werror -cp "$(LIBS)/*" -d $(OUT)/classes $$(find $(SOURCES) -name "*.java") && \
	  jar --create --file $(OUT)/$(JAR) --manifest=$(OUT)/MANIFEST.MF \
	      -C $(OUT)/classes . -C src/main/resources .'
	@echo "built $(OUT)/$(JAR)  (plugin $(VERSION), DT $(DT_VERSION), $(COMPAT))"

# Pure-logic unit tests (no network) via the JUnit console launcher.
test: build
	test -f libs/junit-console.jar || curl -fsSL -o libs/junit-console.jar "$(JUNIT_URL)"
	rm -rf $(OUT)/test-classes && mkdir -p $(OUT)/test-classes
	docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) sh -c '\
	  javac -cp "$(LIBS)/*:libs/junit-console.jar:$(OUT)/classes" -d $(OUT)/test-classes $$(find src/test/java -name "*.java") && \
	  CP="$(OUT)/classes:$(OUT)/test-classes:src/main/resources:$$(ls $(LIBS)/*.jar | tr "\n" ":")" && \
	  java -jar libs/junit-console.jar execute --class-path "$$CP" \
	      --scan-classpath $(OUT)/test-classes --details=summary --disable-banner'

# Build + test every supported DT minor.
all-dt:
	@set -e; for v in $(DT_VERSIONS); do $(MAKE) --no-print-directory test DT_VERSION=$$v; done
	@ls -l build/dt*/$(JAR)

# Dev-only: copy the built JAR to a Dependency-Track test instance and reload it.
# Set DEPLOY_HOST (ssh target) and DEPLOY_DIR (compose dir holding plugins/);
# DT_VERSION must match the instance.
DEPLOY_HOST ?= dt-host
DEPLOY_DIR  ?= ~/dtrack-test
deploy: build
	@test "$(DEPLOY_HOST)" != "dt-host" || { echo "set DEPLOY_HOST=<ssh-target> (and optionally DEPLOY_DIR)"; exit 1; }
	scp $(OUT)/$(JAR) $(DEPLOY_HOST):$(DEPLOY_DIR)/plugins/$(JAR)
	@echo "restart the apiserver to load it:"
	@echo "  ssh $(DEPLOY_HOST) 'cd $(DEPLOY_DIR) && docker compose restart apiserver'"

clean:
	rm -rf build libs
