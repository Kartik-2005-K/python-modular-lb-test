# python-modular-lb-test
A configuration-driven Python test framework for Load Balancer APIs. Features modular architecture, parallel execution, and YAML-based test definition.
# ⚖️ Modular Load Balancer Test Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-success)

A professional, configuration-driven automation framework designed to validate Load Balancer API lifecycles. 

### 🚀 Key Features
* **YAML-Driven:** Test scenarios and environments are defined in `workflow.yaml` without touching code.
* **Parallel Execution:** Uses `concurrent.futures` to speed up pre-fetching of assets.
* **Modular Design:** Decoupled logic (`ActionDispatcher`) makes adding new test steps easy.
* **Mock Integration:** Includes stubbed SSH/RDP checks for simulated infrastructure validation.

---
