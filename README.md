# cluster-api-provider-existinginfra

[![godev](https://img.shields.io/static/v1?label=godev&message=reference&color=00add8)](https://pkg.go.dev/github.com/weaveworks/cluster-api-provider-existinginfra)
[![build](https://github.com/weaveworks/cluster-api-provider-existinginfra/workflows/build/badge.svg)](https://github.com/weaveworks/cluster-api-provider-existinginfra/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/weaveworks/cluster-api-provider-existinginfra)](https://goreportcard.com/report/github.com/weaveworks/cluster-api-provider-existinginfra)
[![codecov.io](https://codecov.io/github/weaveworks/cluster-api-provider-existinginfra/coverage.svg?branch=master)](https://codecov.io/github/weaveworks/cluster-api-provider-existinginfra?branch=master)
[![LICENSE](https://img.shields.io/github/license/weaveworks/cluster-api-provider-existinginfra)](https://github.com/weaveworks/cluster-api-provider-existinginfra/blob/master/LICENSE)
[![Release](https://img.shields.io/github/v/release/weaveworks/cluster-api-provider-existinginfra?include_prereleases)](https://github.com/weaveworks/cluster-api-provider-existinginfra/releases/latest)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://github.com/weaveworks/cluster-api-provider-existinginfra/blob/master/CONTRIBUTING.md)

A Cluster API `v1alpha3` Infrastructure Provider for already-provisioned hosts running Linux.
This controller is split out from and used by [weaveworks/wksctl](https://github.com/weaveworks/wksctl).

## Environment Variables

In order to use the provider within a management cluster, the following environment variables must be set:

- NAMESPACE (the namespace in which to deploy cluster components)
- CONTROL_PLANE_MACHINE_COUNT (how many control plane nodes to create)
- WORKER_MACHINE_COUNT (how many worker nodes to create)

## Machine Pool
Since this provider operates on pre-existing machines, the machine information must be supplied externally. This is done via a secret in the namespace for the cluster. The secret must be named "ip-pool" and contain a JSON document describing the machines in a field called "config". Example:

JSON machine description:

``` json
[{"sshUser": "root",
  "sshKey": <KEY (base64-encoded)>,
  "publicIP": <IP>,
  "publicPort": <PORT (string)>",
  "privateIP": <IP>,
  "privatePort": <PORT (string)>"},
 ...
 ]

```

Secret:

``` yaml
apiVersion: v1
kind: Secret
metadata:
  name: ip-pool
  namespace: demo
type: Opaque
data:
  config: W3sic3NoVXNlciI6ICJlYzItdXNlciIsICJzc2hLZXkiOiAiTFMwdExTMUNSVWRKVGlCU1UwRWdVRkpKVmtGVVJTQkxSVmt0TFMwdExRcE5TVWxGYjJkSlFrRkJTME5CVVVWQlowcElkbWx1TTNWYU5USmhTa2xNY0VKR01WQlVORTU1TkdkSE4xUkZVRTQxTm5Cc01HOXRXazlhYjNoMVVqTllaVlZtTUVFMlZFZzRjMlJVQ21obFR5dFJWSFlyVkhCMGEwSlJaek4zUTFBM05XZFBObk52V2podGVYTkpZV3h2T0dOU1pXdEhXRW95TUV0VVVtcDFhM1o2ZFhKWFQwWjBRWEp0TDFBeU1sTndRbTEwUmpaMmJYa0tUMVJ3WmtkUWVFbFpSMmhGUVN0aVZISmFTVUpPTVcxQ1QwcFhTamw2TjJOT1lURlpOVXBrTm5GMVZWTnVkalpKU1haMVltazNhRlpvYUZWdlFtMHdPR1ZKZFhwNGFYQmpUMDByUkFveFkyZERiVEZOY2s5aFdrWTJjWFZ0U1RacmMySktkeXN4TVZBemIwcHhSVkpoUVhSMWRVeHZOSFpKY2pkaE4wMUdNVlZYYVRaQmJGRkRhSFJPSzBkeFRtdzVUMVYwYVRCMldTOXFDbmgwZUhobGRrWjRibFl3V2prd1NIZFpkV2hGVVRCc05UUktVVFpYVTFKMGEyVmlSR3N2UkdKbFJUVk1TRzFpY0M5aVNWa3ZVVWxFUVZGQlFrRnZTVUpCUkZWTloyWnllSGhSYlhBS2VFc3diQ3R6Um1KUmRITTNSVWszYVZObllrbDJNQzlGVW1sclpISXdVazlPUVM4cmJWTmhiMjl4TVZOTk1VbG5TRzR4VkVndlFrbHpZMEkzWVRCVFRWSkllV0ZJUm1sdE1UQlVUUXBMZFZCWVYwdDVVazlRYTNNeVVDOUxPQ3N4V1RWRlMwVlJjalp6ZEU5RmFDOWphemQ0TVdKME4weFJRMVpUU1VWRWVEVXZNRVJqT1N0U2MxZFRiVWxXZG5WbFUwazRRbFI0VUdFd0NqbFBNRFJYWVVsdWIzWlFkVTAwY0hSeGNqTTJhVEpST1ZONlJYbFNSQzl6T1VGNFIwcDBSWE5CTTFac1JWbDVXRmxJWnpGckx5OUpMMlU1VkVWRE5sVk5jVTVLUXpGMk1VNHJjekVLT1hsUVYySmhSVnBHUm1oNWIxUkxkSE41TkhneWFITnZaV0UwVHl0RE5XVlljamxDU0hGMWNIUmpWWGRCU0c1VlVIUlFhazVJWTI1dGJVWTJVRXB3Y0d3MlIyVTNPVGh2WjNkb2VRcFhRMnhhTUZaWVdFODVUVk16WkRNdmIwZERaR1ZOZVZrMVpVVkRaMWxGUVhoNk1FTlplRTFPUmtKcVpHdDRRVVJOTUV3clZ6QlpZbkpCWkU1RFlVVXZWMmhLYlM5b1pWQlFlbEl5Q2tablZqVmtjU3RSUW1kRlYyTnJjRTVYY3pjNVUxTllPVmxEUzFrMVRIbHNRMEZhZWtoUlRUVjRlakkwV25JeFZYcFBTbEJSZFVKQ05FMW5lREZoYjNwWU1uSm1lbGc1S3pkTmEwd0thazFUV0ZoNGVtZERXRVp4SzFrdlVEZEdSM2cyUmxaVGNEaDFiR1IzWjIwd1UwcGhhR3B6VTJnNFZqTTViRWt3TjA5VlEyZFpSVUZ3VkV4dFJ6TkRNakZ5ZVhaWFZIRktWRzl1VkFvd1dXOWxaRzg1ZDNkT2NXWmlLekZYVkVSWk9XaGhWVXRTYlRodmFucFZiRFV3YW01VVNtNVpla05VU21FM05WVkNaRzlyT0UxaVkxaGFUV1pUUkVad2RFUXlUbGhYTDJSWFNpdDZDbGxNVnl0UGFVbEJVVE5VZEVnNVZrYzBlRkZhTm1oelFYUldjVGczY1ZCSGNUWmtNRzV3VW0xQ2NVOXhTMUF4V205a1JVeFFLMUl6ZFdOV1RWaG1WM1JMUWtSUFJWcE9iMVZxYTBNS1oxbEJObEV5WjFsVGRrUjJTMHB3WWsxRWNWQlhaemhDTmtFeVpHdEJSVU5UVDI4MmVqbHFXV2N4UlRkdVdEZFBlamhyUjFsVE4xQTBjU3RMZFhCdVIySllUalpYWVdGMk16QTBkd3A2WXpOQkwwRnVZblZTTjBSWGFGRTNlbnBCYlZCcFVVcHVXVlZIVlN0VWJUUTNMMnRNYkM5SFR6TjFSbWxSUm1Od0wzcFJUSEZUUW1adE5WaEVjWGQ1U1cwelVsVkhiemhqV0hkM0NuY3JlQ3REWm5KSkswTjBhVVYxWjFNeU1WWnZNVkZMUW1kSVUwVTFlSEUxYzB0NlltNHdOWFphUlU5aFNWZFpkRnB1YXpOcFZUZDBjRkZHWTFKTU9IbHFjMmhDT1ZoS2FXMTRaMUFLV1RkSGVtdFViRTVXYTFndlQwaGhabGt3U2xKalJHSklMMDE1Wm5CaVVGVTNibkZ5TkRWaVp5OVNNbmxZZFVrMmNtNWlkMWh2UlRFMmNqZEhVSFEyVWpSbmJHMXFSMUpsU1U0MmRBcGpPR0pHVFZKT1pFWnRNV1ZoVUc1TFdVeHpjVFpEVm1weWVrc3ZkamRMVTFFeFZEaE1WM3B0VEZCSE5VRnZSMEZLVkhGbGJYUktTRWRJVGxSMk5URnhhVkpWZFhwdlNXVTFjMjFZQ2xvNGMxUTVkVXhVV21rMWRVSjBkbmt4VlV0UlUydDBiM2c1ZUhsVVRrSktlRTFMV1VGTmFsTXJiRnBIYjNVclpETmhObmxZTlRKVVpFVm1kWEZPUTJWNGQyZ3dWMGhOU25wbVN6SUtObVIwWVVoRVpYVnFkamhaYmxKS2JHZHhOVVJMV21sMWRrOWpaR0ZHU1RSdFMycDNaazluV0VWaU5HTmpRVk5CUTNwR09IRktWazB5ZEZaVFVFMUtZMlZOTUQwS0xTMHRMUzFGVGtRZ1VsTkJJRkJTU1ZaQlZFVWdTMFZaTFMwdExTMD0iLCAicHVibGljSVAiOiAiNTQuNjcuNzUuMjUzIiwgInB1YmxpY1BvcnQiOiAiMjIiLCAicHJpdmF0ZUlQIjogIjE3Mi4zMS4xMi4yMDQiLCAicHJpdmF0ZVBvcnQiOiAiMjIifSwgeyJzc2hVc2VyIjogImVjMi11c2VyIiwgInNzaEtleSI6ICJMUzB0TFMxQ1JVZEpUaUJTVTBFZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFFwTlNVbEZiMmRKUWtGQlMwTkJVVVZCWjBwSWRtbHVNM1ZhTlRKaFNrbE1jRUpHTVZCVU5FNTVOR2RITjFSRlVFNDFObkJzTUc5dFdrOWFiM2gxVWpOWVpWVm1NRUUyVkVnNGMyUlVDbWhsVHl0UlZIWXJWSEIwYTBKUlp6TjNRMUEzTldkUE5uTnZXamh0ZVhOSllXeHZPR05TWld0SFdFb3lNRXRVVW1wMWEzWjZkWEpYVDBaMFFYSnRMMUF5TWxOd1FtMTBSaloyYlhrS1QxUndaa2RRZUVsWlIyaEZRU3RpVkhKYVNVSk9NVzFDVDBwWFNqbDZOMk5PWVRGWk5VcGtObkYxVlZOdWRqWkpTWFoxWW1rM2FGWm9hRlZ2UW0wd09HVkpkWHA0YVhCalQwMHJSQW94WTJkRGJURk5jazloV2tZMmNYVnRTVFpyYzJKS2R5c3hNVkF6YjBweFJWSmhRWFIxZFV4dk5IWkpjamRoTjAxR01WVlhhVFpCYkZGRGFIUk9LMGR4VG13NVQxVjBhVEIyV1M5cUNuaDBlSGhsZGtaNGJsWXdXamt3U0hkWmRXaEZVVEJzTlRSS1VUWlhVMUowYTJWaVJHc3ZSR0psUlRWTVNHMWljQzlpU1ZrdlVVbEVRVkZCUWtGdlNVSkJSRlZOWjJaeWVIaFJiWEFLZUVzd2JDdHpSbUpSZEhNM1JVazNhVk5uWWtsMk1DOUZVbWxyWkhJd1VrOU9RUzhyYlZOaGIyOXhNVk5OTVVsblNHNHhWRWd2UWtselkwSTNZVEJUVFZKSWVXRklSbWx0TVRCVVRRcExkVkJZVjB0NVVrOVFhM015VUM5TE9Dc3hXVFZGUzBWUmNqWnpkRTlGYUM5amF6ZDRNV0owTjB4UlExWlRTVVZFZURVdk1FUmpPU3RTYzFkVGJVbFdkblZsVTBrNFFsUjRVR0V3Q2psUE1EUlhZVWx1YjNaUWRVMDBjSFJ4Y2pNMmFUSlJPVk42UlhsU1JDOXpPVUY0UjBwMFJYTkJNMVpzUlZsNVdGbElaekZyTHk5SkwyVTVWRVZETmxWTmNVNUtRekYyTVU0cmN6RUtPWGxRVjJKaFJWcEdSbWg1YjFSTGRITjVOSGd5YUhOdlpXRTBUeXRETldWWWNqbENTSEYxY0hSalZYZEJTRzVWVUhSUWFrNUlZMjV0YlVZMlVFcHdjR3cyUjJVM09UaHZaM2RvZVFwWFEyeGFNRlpZV0U4NVRWTXpaRE12YjBkRFpHVk5lVmsxWlVWRFoxbEZRWGg2TUVOWmVFMU9Sa0pxWkd0NFFVUk5NRXdyVnpCWlluSkJaRTVEWVVVdlYyaEtiUzlvWlZCUWVsSXlDa1puVmpWa2NTdFJRbWRGVjJOcmNFNVhjemM1VTFOWU9WbERTMWsxVEhsc1EwRmFla2hSVFRWNGVqSTBXbkl4VlhwUFNsQlJkVUpDTkUxbmVERmhiM3BZTW5KbWVsZzVLemROYTB3S2FrMVRXRmg0ZW1kRFdFWnhLMWt2VURkR1IzZzJSbFpUY0RoMWJHUjNaMjB3VTBwaGFHcHpVMmc0VmpNNWJFa3dOMDlWUTJkWlJVRndWRXh0UnpORE1qRnllWFpYVkhGS1ZHOXVWQW93V1c5bFpHODVkM2RPY1daaUt6RlhWRVJaT1doaFZVdFNiVGh2YW5wVmJEVXdhbTVVU201WmVrTlVTbUUzTlZWQ1pHOXJPRTFpWTFoYVRXWlRSRVp3ZEVReVRsaFhMMlJYU2l0NkNsbE1WeXRQYVVsQlVUTlVkRWc1VmtjMGVGRmFObWh6UVhSV2NUZzNjVkJIY1Raa01HNXdVbTFDY1U5eFMxQXhXbTlrUlV4UUsxSXpkV05XVFZobVYzUkxRa1JQUlZwT2IxVnFhME1LWjFsQk5sRXlaMWxUZGtSMlMwcHdZazFFY1ZCWFp6aENOa0V5Wkd0QlJVTlRUMjgyZWpscVdXY3hSVGR1V0RkUGVqaHJSMWxUTjFBMGNTdExkWEJ1UjJKWVRqWlhZV0YyTXpBMGR3cDZZek5CTDBGdVluVlNOMFJYYUZFM2VucEJiVkJwVVVwdVdWVkhWU3RVYlRRM0wydE1iQzlIVHpOMVJtbFJSbU53TDNwUlRIRlRRbVp0TlZoRWNYZDVTVzB6VWxWSGJ6aGpXSGQzQ25jcmVDdERabkpKSzBOMGFVVjFaMU15TVZadk1WRkxRbWRJVTBVMWVIRTFjMHQ2WW00d05YWmFSVTloU1ZkWmRGcHVhek5wVlRkMGNGRkdZMUpNT0hscWMyaENPVmhLYVcxNFoxQUtXVGRIZW10VWJFNVdhMWd2VDBoaFpsa3dTbEpqUkdKSUwwMTVabkJpVUZVM2JuRnlORFZpWnk5U01ubFlkVWsyY201aWQxaHZSVEUyY2pkSFVIUTJValJuYkcxcVIxSmxTVTQyZEFwak9HSkdUVkpPWkVadE1XVmhVRzVMV1V4emNUWkRWbXB5ZWtzdmRqZExVMUV4VkRoTVYzcHRURkJITlVGdlIwRktWSEZsYlhSS1NFZElUbFIyTlRGeGFWSlZkWHB2U1dVMWMyMVlDbG80YzFRNWRVeFVXbWsxZFVKMGRua3hWVXRSVTJ0MGIzZzVlSGxVVGtKS2VFMUxXVUZOYWxNcmJGcEhiM1VyWkROaE5ubFlOVEpVWkVWbWRYRk9RMlY0ZDJnd1YwaE5TbnBtU3pJS05tUjBZVWhFWlhWcWRqaFpibEpLYkdkeE5VUkxXbWwxZGs5alpHRkdTVFJ0UzJwM1prOW5XRVZpTkdOalFWTkJRM3BHT0hGS1ZrMHlkRlpUVUUxS1kyVk5NRDBLTFMwdExTMUZUa1FnVWxOQklGQlNTVlpCVkVVZ1MwVlpMUzB0TFMwPSIsICJwdWJsaWNJUCI6ICI1NC4yMTkuMTgzLjk0IiwgInB1YmxpY1BvcnQiOiAiMjIiLCAicHJpdmF0ZUlQIjogIjE3Mi4zMS4yOS4xODMiLCAicHJpdmF0ZVBvcnQiOiAiMjIifSwgeyJzc2hVc2VyIjogImVjMi11c2VyIiwgInNzaEtleSI6ICJMUzB0TFMxQ1JVZEpUaUJTVTBFZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFFwTlNVbEZiMmRKUWtGQlMwTkJVVVZCWjBwSWRtbHVNM1ZhTlRKaFNrbE1jRUpHTVZCVU5FNTVOR2RITjFSRlVFNDFObkJzTUc5dFdrOWFiM2gxVWpOWVpWVm1NRUUyVkVnNGMyUlVDbWhsVHl0UlZIWXJWSEIwYTBKUlp6TjNRMUEzTldkUE5uTnZXamh0ZVhOSllXeHZPR05TWld0SFdFb3lNRXRVVW1wMWEzWjZkWEpYVDBaMFFYSnRMMUF5TWxOd1FtMTBSaloyYlhrS1QxUndaa2RRZUVsWlIyaEZRU3RpVkhKYVNVSk9NVzFDVDBwWFNqbDZOMk5PWVRGWk5VcGtObkYxVlZOdWRqWkpTWFoxWW1rM2FGWm9hRlZ2UW0wd09HVkpkWHA0YVhCalQwMHJSQW94WTJkRGJURk5jazloV2tZMmNYVnRTVFpyYzJKS2R5c3hNVkF6YjBweFJWSmhRWFIxZFV4dk5IWkpjamRoTjAxR01WVlhhVFpCYkZGRGFIUk9LMGR4VG13NVQxVjBhVEIyV1M5cUNuaDBlSGhsZGtaNGJsWXdXamt3U0hkWmRXaEZVVEJzTlRSS1VUWlhVMUowYTJWaVJHc3ZSR0psUlRWTVNHMWljQzlpU1ZrdlVVbEVRVkZCUWtGdlNVSkJSRlZOWjJaeWVIaFJiWEFLZUVzd2JDdHpSbUpSZEhNM1JVazNhVk5uWWtsMk1DOUZVbWxyWkhJd1VrOU9RUzhyYlZOaGIyOXhNVk5OTVVsblNHNHhWRWd2UWtselkwSTNZVEJUVFZKSWVXRklSbWx0TVRCVVRRcExkVkJZVjB0NVVrOVFhM015VUM5TE9Dc3hXVFZGUzBWUmNqWnpkRTlGYUM5amF6ZDRNV0owTjB4UlExWlRTVVZFZURVdk1FUmpPU3RTYzFkVGJVbFdkblZsVTBrNFFsUjRVR0V3Q2psUE1EUlhZVWx1YjNaUWRVMDBjSFJ4Y2pNMmFUSlJPVk42UlhsU1JDOXpPVUY0UjBwMFJYTkJNMVpzUlZsNVdGbElaekZyTHk5SkwyVTVWRVZETmxWTmNVNUtRekYyTVU0cmN6RUtPWGxRVjJKaFJWcEdSbWg1YjFSTGRITjVOSGd5YUhOdlpXRTBUeXRETldWWWNqbENTSEYxY0hSalZYZEJTRzVWVUhSUWFrNUlZMjV0YlVZMlVFcHdjR3cyUjJVM09UaHZaM2RvZVFwWFEyeGFNRlpZV0U4NVRWTXpaRE12YjBkRFpHVk5lVmsxWlVWRFoxbEZRWGg2TUVOWmVFMU9Sa0pxWkd0NFFVUk5NRXdyVnpCWlluSkJaRTVEWVVVdlYyaEtiUzlvWlZCUWVsSXlDa1puVmpWa2NTdFJRbWRGVjJOcmNFNVhjemM1VTFOWU9WbERTMWsxVEhsc1EwRmFla2hSVFRWNGVqSTBXbkl4VlhwUFNsQlJkVUpDTkUxbmVERmhiM3BZTW5KbWVsZzVLemROYTB3S2FrMVRXRmg0ZW1kRFdFWnhLMWt2VURkR1IzZzJSbFpUY0RoMWJHUjNaMjB3VTBwaGFHcHpVMmc0VmpNNWJFa3dOMDlWUTJkWlJVRndWRXh0UnpORE1qRnllWFpYVkhGS1ZHOXVWQW93V1c5bFpHODVkM2RPY1daaUt6RlhWRVJaT1doaFZVdFNiVGh2YW5wVmJEVXdhbTVVU201WmVrTlVTbUUzTlZWQ1pHOXJPRTFpWTFoYVRXWlRSRVp3ZEVReVRsaFhMMlJYU2l0NkNsbE1WeXRQYVVsQlVUTlVkRWc1VmtjMGVGRmFObWh6UVhSV2NUZzNjVkJIY1Raa01HNXdVbTFDY1U5eFMxQXhXbTlrUlV4UUsxSXpkV05XVFZobVYzUkxRa1JQUlZwT2IxVnFhME1LWjFsQk5sRXlaMWxUZGtSMlMwcHdZazFFY1ZCWFp6aENOa0V5Wkd0QlJVTlRUMjgyZWpscVdXY3hSVGR1V0RkUGVqaHJSMWxUTjFBMGNTdExkWEJ1UjJKWVRqWlhZV0YyTXpBMGR3cDZZek5CTDBGdVluVlNOMFJYYUZFM2VucEJiVkJwVVVwdVdWVkhWU3RVYlRRM0wydE1iQzlIVHpOMVJtbFJSbU53TDNwUlRIRlRRbVp0TlZoRWNYZDVTVzB6VWxWSGJ6aGpXSGQzQ25jcmVDdERabkpKSzBOMGFVVjFaMU15TVZadk1WRkxRbWRJVTBVMWVIRTFjMHQ2WW00d05YWmFSVTloU1ZkWmRGcHVhek5wVlRkMGNGRkdZMUpNT0hscWMyaENPVmhLYVcxNFoxQUtXVGRIZW10VWJFNVdhMWd2VDBoaFpsa3dTbEpqUkdKSUwwMTVabkJpVUZVM2JuRnlORFZpWnk5U01ubFlkVWsyY201aWQxaHZSVEUyY2pkSFVIUTJValJuYkcxcVIxSmxTVTQyZEFwak9HSkdUVkpPWkVadE1XVmhVRzVMV1V4emNUWkRWbXB5ZWtzdmRqZExVMUV4VkRoTVYzcHRURkJITlVGdlIwRktWSEZsYlhSS1NFZElUbFIyTlRGeGFWSlZkWHB2U1dVMWMyMVlDbG80YzFRNWRVeFVXbWsxZFVKMGRua3hWVXRSVTJ0MGIzZzVlSGxVVGtKS2VFMUxXVUZOYWxNcmJGcEhiM1VyWkROaE5ubFlOVEpVWkVWbWRYRk9RMlY0ZDJnd1YwaE5TbnBtU3pJS05tUjBZVWhFWlhWcWRqaFpibEpLYkdkeE5VUkxXbWwxZGs5alpHRkdTVFJ0UzJwM1prOW5XRVZpTkdOalFWTkJRM3BHT0hGS1ZrMHlkRlpUVUUxS1kyVk5NRDBLTFMwdExTMUZUa1FnVWxOQklGQlNTVlpCVkVVZ1MwVlpMUzB0TFMwPSIsICJwdWJsaWNJUCI6ICIxMy41Ni4yMjcuMTIyIiwgInB1YmxpY1BvcnQiOiAiMjIiLCAicHJpdmF0ZUlQIjogIjE3Mi4zMS4yMy4xMjYiLCAicHJpdmF0ZVBvcnQiOiAiMjIifSwgeyJzc2hVc2VyIjogImVjMi11c2VyIiwgInNzaEtleSI6ICJMUzB0TFMxQ1JVZEpUaUJTVTBFZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFFwTlNVbEZiMmRKUWtGQlMwTkJVVVZCWjBwSWRtbHVNM1ZhTlRKaFNrbE1jRUpHTVZCVU5FNTVOR2RITjFSRlVFNDFObkJzTUc5dFdrOWFiM2gxVWpOWVpWVm1NRUUyVkVnNGMyUlVDbWhsVHl0UlZIWXJWSEIwYTBKUlp6TjNRMUEzTldkUE5uTnZXamh0ZVhOSllXeHZPR05TWld0SFdFb3lNRXRVVW1wMWEzWjZkWEpYVDBaMFFYSnRMMUF5TWxOd1FtMTBSaloyYlhrS1QxUndaa2RRZUVsWlIyaEZRU3RpVkhKYVNVSk9NVzFDVDBwWFNqbDZOMk5PWVRGWk5VcGtObkYxVlZOdWRqWkpTWFoxWW1rM2FGWm9hRlZ2UW0wd09HVkpkWHA0YVhCalQwMHJSQW94WTJkRGJURk5jazloV2tZMmNYVnRTVFpyYzJKS2R5c3hNVkF6YjBweFJWSmhRWFIxZFV4dk5IWkpjamRoTjAxR01WVlhhVFpCYkZGRGFIUk9LMGR4VG13NVQxVjBhVEIyV1M5cUNuaDBlSGhsZGtaNGJsWXdXamt3U0hkWmRXaEZVVEJzTlRSS1VUWlhVMUowYTJWaVJHc3ZSR0psUlRWTVNHMWljQzlpU1ZrdlVVbEVRVkZCUWtGdlNVSkJSRlZOWjJaeWVIaFJiWEFLZUVzd2JDdHpSbUpSZEhNM1JVazNhVk5uWWtsMk1DOUZVbWxyWkhJd1VrOU9RUzhyYlZOaGIyOXhNVk5OTVVsblNHNHhWRWd2UWtselkwSTNZVEJUVFZKSWVXRklSbWx0TVRCVVRRcExkVkJZVjB0NVVrOVFhM015VUM5TE9Dc3hXVFZGUzBWUmNqWnpkRTlGYUM5amF6ZDRNV0owTjB4UlExWlRTVVZFZURVdk1FUmpPU3RTYzFkVGJVbFdkblZsVTBrNFFsUjRVR0V3Q2psUE1EUlhZVWx1YjNaUWRVMDBjSFJ4Y2pNMmFUSlJPVk42UlhsU1JDOXpPVUY0UjBwMFJYTkJNMVpzUlZsNVdGbElaekZyTHk5SkwyVTVWRVZETmxWTmNVNUtRekYyTVU0cmN6RUtPWGxRVjJKaFJWcEdSbWg1YjFSTGRITjVOSGd5YUhOdlpXRTBUeXRETldWWWNqbENTSEYxY0hSalZYZEJTRzVWVUhSUWFrNUlZMjV0YlVZMlVFcHdjR3cyUjJVM09UaHZaM2RvZVFwWFEyeGFNRlpZV0U4NVRWTXpaRE12YjBkRFpHVk5lVmsxWlVWRFoxbEZRWGg2TUVOWmVFMU9Sa0pxWkd0NFFVUk5NRXdyVnpCWlluSkJaRTVEWVVVdlYyaEtiUzlvWlZCUWVsSXlDa1puVmpWa2NTdFJRbWRGVjJOcmNFNVhjemM1VTFOWU9WbERTMWsxVEhsc1EwRmFla2hSVFRWNGVqSTBXbkl4VlhwUFNsQlJkVUpDTkUxbmVERmhiM3BZTW5KbWVsZzVLemROYTB3S2FrMVRXRmg0ZW1kRFdFWnhLMWt2VURkR1IzZzJSbFpUY0RoMWJHUjNaMjB3VTBwaGFHcHpVMmc0VmpNNWJFa3dOMDlWUTJkWlJVRndWRXh0UnpORE1qRnllWFpYVkhGS1ZHOXVWQW93V1c5bFpHODVkM2RPY1daaUt6RlhWRVJaT1doaFZVdFNiVGh2YW5wVmJEVXdhbTVVU201WmVrTlVTbUUzTlZWQ1pHOXJPRTFpWTFoYVRXWlRSRVp3ZEVReVRsaFhMMlJYU2l0NkNsbE1WeXRQYVVsQlVUTlVkRWc1VmtjMGVGRmFObWh6UVhSV2NUZzNjVkJIY1Raa01HNXdVbTFDY1U5eFMxQXhXbTlrUlV4UUsxSXpkV05XVFZobVYzUkxRa1JQUlZwT2IxVnFhME1LWjFsQk5sRXlaMWxUZGtSMlMwcHdZazFFY1ZCWFp6aENOa0V5Wkd0QlJVTlRUMjgyZWpscVdXY3hSVGR1V0RkUGVqaHJSMWxUTjFBMGNTdExkWEJ1UjJKWVRqWlhZV0YyTXpBMGR3cDZZek5CTDBGdVluVlNOMFJYYUZFM2VucEJiVkJwVVVwdVdWVkhWU3RVYlRRM0wydE1iQzlIVHpOMVJtbFJSbU53TDNwUlRIRlRRbVp0TlZoRWNYZDVTVzB6VWxWSGJ6aGpXSGQzQ25jcmVDdERabkpKSzBOMGFVVjFaMU15TVZadk1WRkxRbWRJVTBVMWVIRTFjMHQ2WW00d05YWmFSVTloU1ZkWmRGcHVhek5wVlRkMGNGRkdZMUpNT0hscWMyaENPVmhLYVcxNFoxQUtXVGRIZW10VWJFNVdhMWd2VDBoaFpsa3dTbEpqUkdKSUwwMTVabkJpVUZVM2JuRnlORFZpWnk5U01ubFlkVWsyY201aWQxaHZSVEUyY2pkSFVIUTJValJuYkcxcVIxSmxTVTQyZEFwak9HSkdUVkpPWkVadE1XVmhVRzVMV1V4emNUWkRWbXB5ZWtzdmRqZExVMUV4VkRoTVYzcHRURkJITlVGdlIwRktWSEZsYlhSS1NFZElUbFIyTlRGeGFWSlZkWHB2U1dVMWMyMVlDbG80YzFRNWRVeFVXbWsxZFVKMGRua3hWVXRSVTJ0MGIzZzVlSGxVVGtKS2VFMUxXVUZOYWxNcmJGcEhiM1VyWkROaE5ubFlOVEpVWkVWbWRYRk9RMlY0ZDJnd1YwaE5TbnBtU3pJS05tUjBZVWhFWlhWcWRqaFpibEpLYkdkeE5VUkxXbWwxZGs5alpHRkdTVFJ0UzJwM1prOW5XRVZpTkdOalFWTkJRM3BHT0hGS1ZrMHlkRlpUVUUxS1kyVk5NRDBLTFMwdExTMUZUa1FnVWxOQklGQlNTVlpCVkVVZ1MwVlpMUzB0TFMwPSIsICJwdWJsaWNJUCI6ICIzLjEwMS42Ny4zMiIsICJwdWJsaWNQb3J0IjogIjIyIiwgInByaXZhdGVJUCI6ICIxNzIuMzEuMjcuMTUiLCAicHJpdmF0ZVBvcnQiOiAiMjIifV0K
```

where the config field contains a base64-encoded version of the JSON document.

## Getting Help

If you have any questions about, feedback for or problems with `cluster-api-provider-existinginfra`:

- Invite yourself to the [Weave Users Slack](https://slack.weave.works/).
- Ask a question on the [#general](https://weave-community.slack.com/messages/general/) Slack channel.
- [File an issue](https://github.com/weaveworks/cluster-api-provider-existinginfra/issues/new).

Your feedback is always welcome!

## License

[Apache 2.0](LICENSE)
