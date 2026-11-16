# Writing attacks

Add entries to a YAML file in `src/dyepack/attacks/chains/`:

    - id: unique_name
      channel: tool_output          # or tool_poisoning
      surface: email                # email | web | file | tool_description
      effort: 1                     # 1 trivial .. 5 hard for the attacker
      target: api_key               # api_key | ssn
      payload: |
        text injected into the surface. Placeholders: {attacker_email} {attacker_url}
      # target_tool: fetch_url      # required when surface is tool_description

Variants: `dyepack run --mutators base64,homoglyph,zero_width` adds mutated copies
(each one effort point harder).
