# pihole-operator
An operator to Deploy Pihole

## Description
Goal of this project was to supply a way to declaratively configure a Pihole instance 

### Feature goals

1. Functional Pihole [x]
2. Blocklists []
3. Whitelist []
4. Records []

## installation

```bash
git clone https://github.com/duchaineo1/pihole-operator.git
cd pihole-operator/
pushd dist/chart
helm install -n pihole-operator pihole-operator . -f values.yaml
podp
kubectl apply -f config/samples/cache_v1alpha1_pihole.yaml
```

## Contributing

Feel free to open a PR with your suggested change!

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

