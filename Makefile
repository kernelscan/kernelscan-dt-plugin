# Build the KernelScan Dependency-Track analyzer plugin.
#
# The DT plugin API is not published to Maven Central, so the compile classpath
# is extracted from the pinned official apiserver image — which also makes the
# DT-version coupling explicit: a plugin binary targets one DT release.
# Everything runs in containers; the only local requirement is Docker.

DT_VERSION ?= 5.0.2
DT_IMAGE   ?= ghcr.io/dependencytrack/apiserver:$(DT_VERSION)
JDK_IMAGE  ?= eclipse-temurin:25-jdk
JUNIT_URL  ?= https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.11.3/junit-platform-console-standalone-1.11.3.jar
VERSION    := $(shell cat VERSION)
JAR        := kernelscan-dt-plugin.jar

# Compile-classpath jars, globbed from the image's lib/.
LIB_PATTERNS := plugin-api- vuln-analysis-api- cyclonedx-proto- \
                protobuf-java- slf4j-api- jackson-core- jackson-databind- \
                jackson-annotations- jspecify-

.PHONY: all libs build test clean deploy version

all: build

version:
	@echo "plugin $(VERSION), target Dependency-Track $(DT_VERSION)"

libs:
	rm -rf libs && mkdir -p libs
	docker create --name ksdtp-extract $(DT_IMAGE) >/dev/null
	docker cp ksdtp-extract:/opt/owasp/dependency-track/lib /tmp/ksdtp-lib
	docker rm ksdtp-extract >/dev/null
	@for p in $(LIB_PATTERNS); do \
	  cp /tmp/ksdtp-lib/$$p*.jar libs/ 2>/dev/null || echo "WARN: no jar matching $$p*"; \
	done
	rm -rf /tmp/ksdtp-lib
	@ls libs

build:
	@test -d libs || { echo "run 'make libs' first"; exit 1; }
	rm -rf build && mkdir -p build/classes
	printf 'Implementation-Title: kernelscan-dt-plugin\nImplementation-Version: %s\nX-DependencyTrack-Version: %s\n' \
	  "$(VERSION)" "$(DT_VERSION)" > build/MANIFEST.MF
	docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) sh -c '\
	  javac -Xlint:all -cp "libs/*" -d build/classes $$(find src/main/java -name "*.java") && \
	  jar --create --file build/$(JAR) --manifest=build/MANIFEST.MF \
	      -C build/classes . -C src/main/resources .'
	@echo "built build/$(JAR)  (plugin $(VERSION), DT $(DT_VERSION))"

# Pure-logic unit tests (no network) via the JUnit console launcher.
test:
	@test -d libs || { echo "run 'make libs' first"; exit 1; }
	mkdir -p libs && test -f libs/junit-console.jar || curl -fsSL -o libs/junit-console.jar "$(JUNIT_URL)"
	rm -rf build/test-classes && mkdir -p build/test-classes
	docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) sh -c '\
	  javac -cp "libs/*:build/classes" -d build/test-classes $$(find src/test/java -name "*.java") && \
	  CP="build/classes:build/test-classes:src/main/resources:$$(ls libs/*.jar | tr "\n" ":")" && \
	  java -jar libs/junit-console.jar execute --class-path "$$CP" \
	      --scan-classpath build/test-classes --details=summary --disable-banner'

# Dev-only: push to the m2 test instance (kernelscan-ops/dtrack-test).
deploy: build
	scp build/$(JAR) mac-mini-m2:~/dtrack-test/plugins/$(JAR)
	@echo "restart the apiserver to load it:"
	@echo "  ssh mac-mini-m2 'zsh -lc \"cd ~/dtrack-test && docker compose restart apiserver\"'"

clean:
	rm -rf build libs
