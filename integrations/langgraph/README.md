# LangGraph integration

Status: implemented.

`GatewayToolNode` is a graph node. It reads tool calls from the last message and sends each one through `agentshield_sdk.Client.call_tool`. The constructor does not accept a list of Python functions. There is no path that runs a tool inside this process.

A call must include `resource` in its arguments. `operation` defaults to the tool name. `deny` and `require_approval` become an error tool message. The node does not call execute for those outcomes, because `call_tool` stops first.

This is not a LangChain tool wrapper. LangChain and CrewAI remain unsupported.

```python
from agentshield_langgraph import GatewayToolNode

graph.add_node("tools", GatewayToolNode(client))
```
