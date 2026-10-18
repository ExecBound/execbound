{#- SPDX-License-Identifier: Apache-2.0 -#}
# Optional developer demo, on this workspace's sample targets or on a workspace holding
# only synthetic fixtures. sandbox.json is a compatibility filename for its configuration.
# The demo directory holds an agent's API key, so it is made yours alone first.
mkdir -p ~/execbound-demo && chmod 700 ~/execbound-demo && cd ~/execbound-demo
# Save the configuration here as sandbox.json: Download demo configuration on the Sample
# targets card, or Download sample configuration in a workspace of synthetic fixtures.
# Then save an agent's API key, issued on the API keys page, as agent-a.token, one line,
# and add to sandbox.json:  "credentials": {"agent_a": "agent-a.token"}
# Synthetic fixtures need a second agent's key too, saved as agent-b.token, and instead:
#   "credentials": {"agent_a": "agent-a.token", "agent_b": "agent-b.token"}
# A key issued for sample targets outlives the demo: keep each key file readable by you alone.
chmod 600 *.token
export EXECBOUND_URL={{ origin }}
# all runs boundary and decide, then the shared budget beat on synthetic fixtures only.
execbound-demo --private . all
# On sample targets the demo needs them as their facts record them: once a run or your
# agent has isolated one, refresh the sample facts and download the configuration again.
