# sing-box Rule

This repository automatically **fetches** and **converts** daily rules from [@blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) into JSON and SRS files.

## Overview

- **Goal**: Collect `.list` files from the [ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) repository (specifically the `rule/QuantumultX` folder), parse them using our Python script, and generate `.json` plus optional `.srs` rule files for SingBox or other rule-based tools.  
- **Automation**: A **GitHub Actions** workflow runs daily (as scheduled) to pull the latest `.list` files, parse them, then commit/push any updates back to this repo.

## Credits
- Rules Source: [@blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- Inspiration: [@umonaca’s sing-box-geosite](https://github.com/umonaca/sing-box-geosite)
