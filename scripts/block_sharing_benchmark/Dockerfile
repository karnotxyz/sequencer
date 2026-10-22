FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libgmp10 libstdc++6 libgcc-s1 python3 python3-venv tar && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/cairo && /opt/cairo/bin/pip install --no-cache-dir cairo-lang==0.14.1a0
ENV PATH="/opt/cairo/bin:${PATH}"
WORKDIR /home/runner/work/sequencer/sequencer
COPY . .
ENV RUST_MIN_STACK=16777216
CMD ["python3", "scripts/block_sharing_benchmark/run_cluster.py"]
