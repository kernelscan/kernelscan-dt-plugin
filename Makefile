# Build the KernelScan DT plugin without Maven: the DT plugin API is not
# published to Maven Central, so the compile classpath is extracted from the
# pinned official apiserver image. This also pins the version coupling — a
# plugin binary targets exactly one DT release.

DT_IMAGE   ?= ghcr.io/dependencytrack/apiserver:5.0.2
JDK_IMAGE  ?= eclipse-temurin:25-jdk
JAR        := kernelscan-dt-plugin.jar

# Jars needed for compilation (globbed from the image's lib/).
LIB_PATTERNS := plugin-api- vuln-data-source-api- cyclonedx-proto- \
                protobuf-java- slf4j-api- jackson-core- jackson-databind- \
                jackson-annotations- jspecify-

.PHONY: all libs build clean deploy

all: build

libs:
	rm -rf libs && mkdir -p libs
	docker create --name ksdtp-extract $(DT_IMAGE) >/dev/null
	docker cp ksdtp-extract:/opt/owasp/dependency-track/lib /tmp/ksdtp-lib
	docker rm ksdtp-extract >/dev/null
	@for p in $(LIB_PATTERNS); do \
	  cp /tmp/ksdtp-lib/$$p*.jar libs/ 2>/dev/null \
	    || echo "WARN: no jar matching $$p*"; \
	done
	rm -rf /tmp/ksdtp-lib
	@ls libs

build:
	@test -d libs || { echo "run 'make libs' first"; exit 1; }
	rm -rf build && mkdir -p build/classes
	docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) sh -c '\
	  javac -cp "libs/*" -d build/classes $$(find src/main/java -name "*.java") && \
	  jar --create --file build/$(JAR) -C build/classes . -C src/main/resources .'
	@echo "built build/$(JAR)"
	@docker run --rm -v $(PWD):/work -w /work $(JDK_IMAGE) jar --list --file build/$(JAR)

# Dev-only: push to the m2 test instance (kernelscan-ops/dtrack-test).
deploy: build
	scp build/$(JAR) mac-mini-m2:~/dtrack-test/plugins/$(JAR)
	@echo "now add the volume mount to dtrack-test's compose (see README) and:"
	@echo "  ssh mac-mini-m2 'zsh -lc \"cd ~/dtrack-test && docker compose restart apiserver\"'"

clean:
	rm -rf build libs
