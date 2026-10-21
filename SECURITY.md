# Security policy

## Intended use

This repository intentionally contains a proof of a critical PHP vulnerability.
Use it only with the included isolated Docker/Kubernetes targets or systems you
own and have explicitly authorized for security testing.

The PoC intentionally accepts only local lab endpoints and one fixed benign
command. Requests to add arbitrary remote targeting, command selection,
persistence, credential access, or production exploitation are outside this
project's scope.

## Reporting a repository issue

Do not open a public issue for a new vulnerability in the lab's orchestration,
CI, or supporting code if disclosure would put users at risk. Use this GitHub
repository's private security-advisory reporting feature instead.

The two PHP core vulnerabilities documented here are already public. Report
new PHP engine vulnerabilities through the PHP project's established security
process rather than this reproduction repository.

## Operational warning

The target images are deliberately vulnerable. Do not expose them through a
public port, Ingress, NodePort, LoadBalancer, or shared production network.
Remove test containers, volumes, and the `php-rce-lab` namespace when research
is complete.
