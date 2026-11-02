# Chaos evaluator

Status: implemented in `runtime/gateway/internal/chaos`.

`judge` compares an observation with the scenario's defensive property. A missing observation is failed. An unknown scenario id is error, which is not a pass. The control plane stores that result on the experiment row.
