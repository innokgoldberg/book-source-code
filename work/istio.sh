minikube delete && minikube start  --memory=8g --cpus=4
#this will install k8s v1.23, there is en error with k8s v1.24 with  metrics-server addon
#https://github.com/kubernetes-sigs/metrics-server/issues/1031
#error on kube top nodes:  Error from server (ServiceUnavailable): the server is currently unable to handle the request (get nodes.metrics.k8s.io).
#this fix don't work https://k21academy.com/docker-kubernetes/the-server-is-currently-unable-to-handle-the-request/ (– –kubelet-insecure-tls)
minikube addons enable metrics-server
#need to do 1 time
#curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.13.0 sh -

export PATH="$PATH:/Users/den_fomicev/projects/istio/istio-1.13.0/bin"
istioctl x precheck
istioctl version

istioctl install --set profile=demo -y
kubectl get pods -n istio-system
  helm repo add metallb https://metallb.github.io/metallb
  helm install metallb metallb/metallb -n istio-system
  kubectl get pods -n istio-system --watch
 cat work/metallb-adress-pool.yaml | sed "s@1.1.1.1@"$(minikube ip)"@" | kubectl diff  -f -
 cat work/metallb-adress-pool.yaml | sed "s@1.1.1.1@"$(minikube ip)"@" | kubectl apply  -f -
 kubectl get all -n istio-system
istioctl verify-install
kubectl apply -f istio-1.13.0/samples/addons
kubectl get pods -n istio-system --watch

kubectl create namespace istioinaction
#we will work in istioinaction namespace as default
kubectl config set-context $(kubectl config current-context) \
--namespace=istioinaction

#the contents of modified deployment with istio sidecar in pod of app catalog
istioctl kube-inject -f services/catalog/kubernetes/catalog.yaml > services/catalog/kubernetes/catalog_istio.yaml

#let istio auto inject its code into namespace apps
kubectl label namespace istioinaction istio-injection=enabled


kubectl apply -f services/catalog/kubernetes/catalog.yaml

kubectl get pod # we see 2 containers in the pod
#NAME READY STATUS RESTARTS AGE
#catalog-7c96f7cc66-flm8g 2/2 Running 0 1m

#test the app catalog is working, we expect to see suck json
#{
#  "id": 1,
#  "color": "amber",
#  "department": "Eyewear",
#  "name": "Elinor Glasses",
#  "price": "282.00"
#}
kubectl -n default run -it dummy \
    --image=curlimages/curl \
    --restart=Never \
    --rm \
    --command -- sh -c 'curl -s http://catalog.istioinaction/items/1'

#now deploy the webapp service - it will fetch data from catalog and show it in browser, or allow to access it via api
kubectl apply -f services/webapp/kubernetes/webapp.yaml


kubectl get pods --watch

#test webapp
#{"id":1,"color":"amber","department":"Eyewear","name":"Elinor Glasses","price":"282.00"}
kubectl -n default run -it dummy \
    --image=curlimages/curl \
    --restart=Never \
    --rm \
    --command -- sh -c 'curl -s http://webapp.istioinaction/api/catalog/items/1'

#lets watch it in browser
kubectl port-forward deploy/webapp 8080:8080
open "http://localhost:8080"

#now lets expose web traffic via Istio Ingress
kubectl apply -f ch2/ingress-gateway.yaml

#lets see the routes in istio-ingress through istioctl, we hit / and was redirected to webapp
istioctl proxy-config routes\
 deploy/istio-ingressgateway.istio-system

#NAME          DOMAINS     MATCH                  VIRTUAL SERVICE
#http.8080     *           /*                     webapp-virtualservice.istioinaction
#              *           /healthz/ready*
#              *           /stats/prometheus*

kubectl get gateway
kubectl get virtualservice


 LB_IP="$(minikube ip)"
curl http://$LB_IP/api/catalog/items/1

istioctl dashboard grafana

while true; do curl http://$LB_IP/api/catalog; sleep .5; done

istioctl dashboard jaeger

#Running
 #the following command from the
 #root of our source code causes all
 #calls to fail with an HTTP 500 error
 #response 100% of the time:
  bash bin/chaos.sh 500 100
# catalog-6cf4b97d-gpckh
# blowups=[object Object]

#now we see 500 error
curl -v http://$LB_IP/api/catalog/items/1
#now lets trigger 500 error only 50% of time to show istio retry possibilities
bash bin/chaos.sh 500 50

#see 500 50% time
while true; do curl http://$LB_IP/api/catalog;echo; sleep .5; done

#now create catalog vs with retry on error policy
kubectl apply -f ch2/catalog-virtualservice.yaml


#now there is noo 500 as 500 request auto retries
while true; do curl http://$LB_IP/api/catalog;echo; sleep .5; done

#remove catalog service 500 behaviour
bash bin/chaos.sh 500 delete
#catalog-6cf4b97d-gpckh
#Deleting 500 rule from catalog-6cf4b97d-gpckh
#blowups=[object Object]%

#lets see the istio ability to route trafic based on deployment labels (let's say version of deployment in this case)
#we create deploment with version: v2 vs version: v1 in services/catalog/kubernetes/catalog-deployment.yaml which is already deployed
#canotical v1 version of catalog
#{
#"id": 1,
#"color": "amber", "department": "Eyewear", "name": "Elinor Glasses", "price": "282.00"
#}
#For v2 of catalog, we have added a new property named imageUrl:
# {
#"id": 1,
#"color": "amber",
#"department": "Eyewear",
#"name": "Elinor Glasses",
#"price": "282.00"
#"imageUrl": "http://lorempixel.com/640/480"
#}

#in v2 version of app we will have  additional field  imageurl in respone and want to route special traffic to this deployment
kubectl apply \
-f services/catalog/kubernetes/catalog-deployment-v2.yaml

#now we have two deployments of service catalog
kubectl get pods

#so we will occasionally have field imageUrl in responses due to balansing over two versions of catalog app (both deploymetns have app:catalog in labels)
while true; do curl http://$LB_IP/api/catalog;echo; sleep .5; done

#first we will create destinationrule in istio to let in know about different versions of app to allow future routing
kubectl apply -f ch2/catalog-destinationrule.yaml

#we change virtualhost for now to allow traffic only to v1 version of app and remove retry policies

cat ch2/catalog-virtualservice-all-v1.yaml | kubectl diff -f -
kubectl apply -f ch2/catalog-virtualservice-all-v1.yaml

#now we will see traffic goes only to v1 version of catalog
while true; do curl http://$LB_IP/api/catalog;echo; sleep .5; done

#Let’s say that for certain users, we want to expose the functionality of v2 of the
#catalog service. Istio gives us the power to control the routing for individual requests and match on things like request path, headers, cookies, and so on.
#If users pass in a specific header, we will allow them to hit the new catalog v2 service. Using a revised VirtualService definition for catalog,
#let’s match on a header called x-dark- launch. We’ll send any requests with that header to catalog v2:
cat  ch2/catalog-virtualservice-dark-v2.yaml | kubectl diff -f -
kubectl apply -f ch2/catalog-virtualservice-dark-v2.yaml

#still only v1 responses from catalog via default route version-v1
while true; do curl http://$LB_IP/api/catalog;echo; sleep .5; done

#we call v2 version of catalog by passing header x-dark-launch: v2, we see imageurl in responce
curl http://$LB_IP/api/catalog -H "x-dark-launch: v2"

#delete created resources to go to next examples clear
kubectl delete deployment,svc,gateway,virtualservice,destinationrule --all -n istioinaction

#Envoy capabilities
#1) service discovery
#2)load balancing
#         Random
#         Round robin
#         Weighted, least request
#         Consistent hashing (sticky)
#3)TRAFFIC AND REQUEST ROUTING
#4)TRAFFIC SHIFTING AND SHADOWING CAPABILITIES
#    shifting with weights for canary releases
#    shadowing with passing a copy of live traffic to apps with test purposes
#5)NETWORK RESILIENCE
#    request timeouts as well as request-level retries (with per-retry timeouts)
#    Additionally, when Envoy calls upstream clusters, it can be configured with bulkheading character- istics like limiting the number of connections
#     or outstanding requests in flight and to fast-fail any that exceed those thresholds (with some jitter on those thresholds).
#      Finally, Envoy can perform outlier detection, which behaves like a circuit breaker, and eject endpoints from the load-balancing pool when they misbehave
#6)HTTP/2 AND GRPC
#7)OBSERVABILITY WITH METRICS COLLECTION (prometheus and outhers)
#8)OBSERVABILITY WITH DISTRIBUTED TRACING (jaeger and outher zipkin based tools
#9)AUTOMATIC TLS TERMINATION AND ORIGINATION
#    Envoy can terminate Transport Level Security (TLS) traffic destined for a specific ser- vice both at the edge of a cluster and deep within a mesh of service proxies.
#    mTLS
#10)RATE LIMITING
#    Resources like databases or caches or shared services may be pro- tected for various reasons:
#     Expensive to call (per-invocation cost)
#     Slow or unpredictable latency
#     Fairness algorithms needed to protect against starvation
#    Especially as services are configured for retries, we don’t want to magnify the effect of certain failures in the system.
#     To help throttle requests in these scenarios, we can use a global rate-limiting service.
#     Envoy can integrate with a rate-limiting service at both the network (per connection) and HTTP (per request) levels.
# 11)EXTENDING ENVOY (add existing filters, custom lua scripts and webassembly scripts)

#envoy can be dynamically configured without reloading service with xDS API services

helm install consul hashicorp/consul --values /Users/den_fomicev/projects/k8s-specs/cluster/vault/helm-consul-values.yml
helm install vault hashicorp/vault --values /Users/den_fomicev/projects/k8s-specs/cluster/vault/helm-vault-values.yml
kubectl exec vault-0 -- vault status

#if we want to restore vault data from backup we MUST NOT geterate cluster-keys.json
 #BACKUP VAULT DATA FROM CONSUL
 kubectl exec --stdin=true --tty=true consul-consul-server-0 -- /bin/sh
 cd /tmp
 consul snapshot save backup.snap
 logout
 kubectl cp consul-consul-server-0:tmp/backup.snap backup.snap

#RESTORE VAULT DATA FROM CONSUL
#do not init or unseal vault, use previous previous cluster-keys.json
kubectl cp backup.snap consul-consul-server-0:tmp/
kubectl exec --stdin=true --tty=true consul-consul-server-0 -- /bin/sh
consul snapshot restore /tmp/backup.snap
consul kv delete vault/core/lock


#if this is first time vault init
kubectl exec vault-0 -- vault operator init -key-shares=2 -key-threshold=2 -format=json > cluster-keys.json


cat cluster-keys.json | jq -r ".unseal_keys_b64[]"
VAULT_SEAL_1=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[]" | head -1)
VAULT_SEAL_2=$(cat cluster-keys.json | jq -r ".unseal_keys_b64[]" | tail -1)

kubectl exec vault-0 -- vault operator unseal $VAULT_SEAL_1
kubectl exec vault-0 -- vault operator unseal $VAULT_SEAL_2
kubectl exec vault-1 -- vault operator unseal $VAULT_SEAL_1
kubectl exec vault-1 -- vault operator unseal $VAULT_SEAL_2
kubectl exec vault-2 -- vault operator unseal $VAULT_SEAL_1
kubectl exec vault-2 -- vault operator unseal $VAULT_SEAL_2
cat cluster-keys.json | jq -r ".root_token"


kubectl exec --stdin=true --tty=true vault-0 -- /bin/sh
######################in vault-0##########################
vault login
vault secrets enable -path=kvv1 -version=1 kv
vault secrets enable -path=kvv2 -version=2 kv
cat <<EOF | vault policy write vault-secrets-operator -
path "kvv1/*" {
  capabilities = ["read"]
}

path "kvv2/data/*" {
  capabilities = ["read"]
}
EOF
######################in vault-0##########################
#################################token auth method##################################
helm repo add ricoberger https://ricoberger.github.io/helm-charts
helm repo update
helm upgrade --install vault-secrets-operator ricoberger/vault-secrets-operator


#*********************************kubernetes auth method***************************
export VAULT_SECRETS_OPERATOR_NAMESPACE=$(kubectl get sa vault-secrets-operator -o jsonpath="{.metadata.namespace}")
export VAULT_SECRET_NAME=$(kubectl get sa vault-secrets-operator -o jsonpath="{.secrets[*]['name']}")
export SA_JWT_TOKEN=$(kubectl get secret $VAULT_SECRET_NAME -o jsonpath="{.data.token}" | base64 --decode; echo)
export SA_CA_CRT=$(kubectl get secret $VAULT_SECRET_NAME -o jsonpath="{.data['ca\.crt']}" | base64 --decode; echo)
export K8S_HOST=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

# To discover the service account issuer the following commands can be used:
kubectl proxy
curl --silent http://127.0.0.1:8001/api/v1/namespaces/default/serviceaccounts/default/token -H "Content-Type: application/json" -X POST -d '{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest"}' | jq -r '.status.token' | cut -d . -f2 | base64 -D
export ISSUER=$(curl --silent http://127.0.0.1:8001/api/v1/namespaces/default/serviceaccounts/default/token -H "Content-Type: application/json" -X POST -d '{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest"}' | jq -r '.status.token' | cut -d . -f2 | base64 -D | jq .iss | tr -d '"')

# Verify the environment variables
env | grep -E 'VAULT_SECRETS_OPERATOR_NAMESPACE|VAULT_SECRET_NAME|SA_JWT_TOKEN|SA_CA_CRT|K8S_HOST|ISSUER'
kubectl exec --stdin=true --tty=true vault-0 -- /bin/sh -c "vault auth enable kubernetes"
kubectl exec --stdin=true --tty=true vault-0 -- /bin/sh -c "vault write auth/kubernetes/config \
                                                              issuer=\"https://$ISSUER\" \
                                                              token_reviewer_jwt=\"$SA_JWT_TOKEN\" \
                                                              kubernetes_host=\"$K8S_HOST\" \
                                                              kubernetes_ca_cert=\"$SA_CA_CRT\""

kubectl exec --stdin=true --tty=true vault-0 -- /bin/sh -c "vault write auth/kubernetes/role/vault-secrets-operator \
                                                              bound_service_account_names=\"vault-secrets-operator\" \
                                                              bound_service_account_namespaces=\"$VAULT_SECRETS_OPERATOR_NAMESPACE\" \
                                                              policies=vault-secrets-operator \
                                                              ttl=24h"

helm upgrade  vault-secrets-operator ricoberger/vault-secrets-operator -f values-vault-secrets-operator-k8s-auth.yaml

#*********************************kubernetes auth method***************************

#################################token auth method##################################
kubectl exec --stdin=true --tty=true vault-0 -- /bin/sh -c "vault token create -period=24h -policy=vault-secrets-operator"
export VAULT_TOKEN=<TOKEN AUTH HERE>
export VAULT_TOKEN_LEASE_DURATION=86400

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: vault-secrets-operator
type: Opaque
data:
  VAULT_TOKEN: $(echo -n "$VAULT_TOKEN" | base64)
  VAULT_TOKEN_LEASE_DURATION: $(echo -n "$VAULT_TOKEN_LEASE_DURATION" | base64)
EOF
helm upgrade  vault-secrets-operator ricoberger/vault-secrets-operator -f values-vault-secrets-operator-token-auth.yaml
#################################token auth method##################################


 kubectl get pod --watch
kubectl  logs  $(kubectl get pods  | grep vault-secrets-operator | awk '{print $1}') -f

######################in vault-0##########################
vault kv put kvv1/example-vaultsecret foo=bar hello=world

vault kv put kvv2/example-vaultsecret foo=bar
vault kv put kvv2/example-vaultsecret hello=world
vault kv put kvv2/example-vaultsecret foo=bar hello=world
######################in vault-0##########################
kubectl apply -f test-secret.yaml #v1 secret
kubectl get secrets
kubectl describe secrets/kvv1-example-vaultsecret
kubectl get secret kvv1-example-vaultsecret -o jsonpath='{.data}' | jq -r .foo | base64 -D

kubectl apply -f test-secret-v2-version.yaml
kubectl describe secrets/kvv2-example-vaultsecret
kubectl get secret kvv2-example-vaultsecret -o jsonpath='{.data}' | jq -r .hello | base64 -D



#4.2.2 Gateway routing with virtual services

#create a simple gateway
kubectl -n istioinaction apply -f ch4/coolstore-gw.yaml

#lets watch envoy listeners
istioctl -n istio-system proxy-config listener deploy/istio-ingressgateway

#ADDRESS PORT  MATCH DESTINATION
#0.0.0.0 8080  ALL   Route: http.8080
#0.0.0.0 15021 ALL   Inline Route: /healthz/ready*
#0.0.0.0 15090 ALL   Inline Route: /stats/prometheus*

#we see strange route here http.8080, lets view details of it

istioctl proxy-config route deploy/istio-ingressgateway \
-o json --name http.8080 -n istio-system

#Our listener is bound to a blackhole default route that routes everything to HTTP 404. We need VirtualService to route trafic from that route to application
#we need the external ip that pod with istio-ingress cant listen, we provide that by usin metallb

#create virtualservice to map gateway with webapp service
kubectl apply -n istioinaction -f ch4/coolstore-vs.yaml

#lets see what changed in route details
istioctl proxy-config route deploy/istio-ingressgateway \
-o json --name http.8080 -n istio-system

#lets deploy a services for out gateway+virtualservice

kubectl config set-context $(kubectl config current-context)  --namespace=istioinaction
kubectl apply -f services/catalog/kubernetes/catalog.yaml
kubectl apply -f services/webapp/kubernetes/webapp.yaml


kubectl get pod --watch

kubectl get gateway
kubectl get virtualservice

 LB_IP="$(minikube ip)"
curl -v http://$LB_IP/api/catalog


#Neither the Istio gateway nor any of the routing rules we declared in the Virtual- Service knows anything about Host: $(minikube ip):80,\
# but it does know about the vir- tual host webapp.istioinaction.io. Let’s override the Host header on our command line, and then the call should work:

curl http://$LB_IP/api/catalog -H "Host: webapp.istioinaction.io"

#4.2.4 Istio ingress gateway vs. Kubernetes Ingress
#When running on Kubernetes, you may ask, “Why doesn’t Istio just use the Kuberne- tes Ingress v1 resource to specify ingress?”
#Istio does support the Kubernetes Ingress v1 resource, but there are significant limitations with the Kubernetes Ingress v1 specification.
#The first limitation is that Kubernetes Ingress v1 is a very simple specification geared toward HTTP workloads.
#Second, the Kubernetes Ingress v1 resource is severely underspecified. There is no common way to specify complex traffic routing rules,
# traffic splitting, or things like traffic shadowing.


#the Kubernetes community is hard at work on the Gateway API to supplant the Ingress v1 API. You can find more information at https://gateway -api.sigs.k8s.io.
#This is different from the Istio Gateway and VirtualService resources covered in this book.

#4.2.5 Istio ingress gateway vs. API gateways
#If we need to be able to identify clients using different security challenges (OpenID Connect [OIDC], OAuth 2.0, Lightweight Directory Access Protocol [LDAP]),
#transform messages (SOAP to REST, gRPC to Rest, body and header text- based transformations, and so on), provide sophisticated business-level rate limiting,
# and have a self-signup or developer portal. Istio’s ingress gateway does not do these things out of the box.
#  For a more capable API gateway—even one built on an Envoy proxy—that can play this role inside and outside your mesh,
#  take a look at something like Solo.io Gloo Edge (https://docs.solo.io/gloo-edge/latest).

#4.3 Securing gateway traffic

#Istio’s gateway implementation allows us to terminate incoming TLS/SSL traffic, pass it through to the backend services,
# redirect any non-TLS traffic to the proper TLS ports, and implement mutual TLS.

#kubectl create -n istio-system secret tls webapp-credential --key ch4/certs/3_application/private/webapp.istioinaction.io.key.pem  --cert ch4/certs/3_application/certs/webapp.istioinaction.io.cert.pem
#kubectl delete secrets -n istio-system webhook-server-cert

#In this step, we create the secret in the istio-system namespace.
# At the time of writ- ing (Istio 1.13.0), the secret used for TLS in the gateway can only be retrieved if it’s in the same namespace as the Istio ingress gateway.
#  The default gateway is run in the istio-system namespace, so that’s where we put the secret. We could run the ingress gateway in a different namespace,
#   but the secret would still have to be in that name- space. For production, you should run the ingress gateway component in its own namespace, separate from istio-system.

 kubectl cp -n default  ch4/certs/3_application/private/webapp.istioinaction.io.key.pem vault-0:tmp/webapp.istioinaction.io.key.pem
 kubectl cp -n default  ch4/certs/3_application/certs/webapp.istioinaction.io.cert.pem vault-0:tmp/webapp.istioinaction.io.cert.pem
 kubectl exec -n default --stdin=true --tty=true vault-0 -- /bin/sh

######################in vault-0##########################
vault kv put kvv2/webapp-credential  tls.crt=@/tmp/webapp.istioinaction.io.cert.pem tls.key=@/tmp/webapp.istioinaction.io.key.pem
vault kv get kvv2/webapp-credential
######################in vault-0##########################
kubectl apply -f webapp-credential-tls.yaml
kubectl describe -n istio-system secrets/webapp-credential
kubectl get secret -n istio-system  webapp-credential -o jsonpath='{.data}' | jq -r  '."tls.crt"' | base64 -D
kubectl get secret -n istio-system  webapp-credential -o jsonpath='{.data}' | jq -r  '."tls.key"' | base64 -D

#as wee see in vault-operator log the secret get its values from vault
 kubectl  logs -n default  $(kubectl get pods -n default  | grep vault-secrets-operator | awk '{print $1}') -f

#now lets add the opportunity to process tls traffic for our gateway
cat ch4/coolstore-gw-tls.yaml | kubectl diff -f -
kubectl apply -f ch4/coolstore-gw-tls.yaml


curl -v -H "Host: webapp.istioinaction.io" https://$LB_IP/api/catalog
#we got error curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 192.168.64.33:443
#This means the certificate presented by the server cannot be verified using the default CA certificate chains.
# Let’s pass in the proper CA certificate chain to our curl client:

curl -v -H "Host: webapp.istioinaction.io" https://$LB_IP/api/catalog  --cacert ch4/certs/2_intermediate/certs/ca-chain.cert.pem

#* successfully set certificate verify locations:
#*   CAfile: ch4/certs/2_intermediate/certs/ca-chain.cert.pem
#  CApath: none
#* TLSv1.2 (OUT), TLS handshake, Client hello (1):
#* LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 192.168.64.33:443
#* Closing connection 0
#curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to 192.168.64.33:443

#The client still cannot verify the certificate! This is because the server certificate is issued for webapp.istioinaction.io,
# and we’re calling the minikube host ($LB_IP, in this case). We can use a curl parameter called --resolve
# that lets us call the service as though it were at webapp.istioinaction.io but then tell curl to use $LB_IP:

curl -H "Host: webapp.istioinaction.io" https://webapp.istioinaction.io:443/api/catalog \
--cacert ch4/certs/2_intermediate/certs/ca-chain.cert.pem  --resolve webapp.istioinaction.io:443:$LB_IP


#we have achieved end-to-end encryption. We’ve secured traffic by encrypting it to the Istio ingress gateway, which terminates the TLS connection and then sends the traffic
# to the backend webapp service running in our service mesh. The hop between the istio-ingressgateway component and the webapp service is encrypted using the identities of the services.
#thus it is secure by default

#lets force http redirect to https to allow only https traffic to service mesh

kubectl apply -f ch4/coolstore-gw-tls-redirect.yaml


curl -v http://$LB_IP/api/catalog -H "Host: webapp.istioinaction.io"
#< HTTP/1.1 301 Moved Permanently
 #< location: https://webapp.istioinaction.io/api/catalog
 #< date: Mon, 03 Oct 2022 12:25:38 GMT
 #< server: istio-envoy
 #< content-length: 0

 #H4.3.3 HTTP traffic with mutual TLS (mTLS)
   #In the previous section, we used standard TLS to allow the server to prove its identity to the client.
   # But what if we want our cluster to verify who the clients are before we accept any traffic from outside the cluster?
   # In the simple TLS scenario, the server sends its public certificate to the client, and the client verifies that it trusts the CA that signed the server’s certificate.
   # We want to have the client send its public certificate and let the server verify that it trusts it.

#canotical unsecure way to create k8s secret with certificate

kubectl create -n istio-system secret \
  generic webapp-credential-mtls --from-file=tls.key=ch4/certs/3_application/private/webapp.istioinaction.io.key.pem \
  --from-file=tls.crt=ch4/certs/3_application/certs/webapp.istioinaction.io.cert.pem \
  --from-file=ca.crt=ch4/certs/2_intermediate/certs/ca-chain.cert.pem
kubectl delete secrets -n istio-system webapp-credential-mtls

#we copied these two keys before
# kubectl cp -n default  ch4/certs/3_application/private/webapp.istioinaction.io.key.pem vault-0:tmp/webapp.istioinaction.io.key.pem
# kubectl cp -n default  ch4/certs/3_application/certs/webapp.istioinaction.io.cert.pem vault-0:tmp/webapp.istioinaction.io.cert.pem
 kubectl cp -n default  ch4/certs/2_intermediate/certs/ca-chain.cert.pem vault-0:tmp/ca-chain.cert.pem

 kubectl exec -n default --stdin=true --tty=true vault-0 -- /bin/sh

######################in vault-0##########################
vault kv put kvv2/webapp-credential-mtls  tls.crt=@/tmp/webapp.istioinaction.io.cert.pem tls.key=@/tmp/webapp.istioinaction.io.key.pem ca.crt=@/tmp/ca-chain.cert.pem
vault kv get kvv2/webapp-credential-mtls
######################in vault-0##########################
kubectl apply -f webapp-credential-mtls.yaml
kubectl describe -n istio-system secrets/webapp-credential-mtls
kubectl get secret -n istio-system  webapp-credential-mtls -o jsonpath='{.data}' | jq -r  '."tls.crt"' | base64 -D
kubectl get secret -n istio-system  webapp-credential-mtls -o jsonpath='{.data}' | jq -r  '."tls.key"' | base64 -D
kubectl get secret -n istio-system  webapp-credential-mtls -o jsonpath='{.data}' | jq -r  '."ca.crt"' | base64 -D

#lets appy mtls configuration of the gateway
kubectl apply -f ch4/coolstore-gw-mtls.yaml

curl -H "Host: webapp.istioinaction.io" https://webapp.istioinaction.io:443/api/catalog \
--cacert ch4/certs/2_intermediate/certs/ca-chain.cert.pem  --resolve webapp.istioinaction.io:443:$LB_IP
#curl: (35) error:1401E410:SSL routines:CONNECT_CR_FINISHED:sslv3 alert handshake failure
#This call is rejected because the SSL handshake wasn’t successful.
# We are only passing the CA certificate chain to the curl command; we need to also pass the client’s certifi- cate and private key for mTLS

curl -H "Host: webapp.istioinaction.io" https://webapp.istioinaction.io:443/api/catalog \
--cacert ch4/certs/2_intermediate/certs/ca-chain.cert.pem  --resolve webapp.istioinaction.io:443:$LB_IP \
--cert ch4/certs/4_client/certs/webapp.istioinaction.io.cert.pem --key ch4/certs/4_client/private/webapp.istioinaction.io.key.pem


#Istio gateway SDS
 #An Istio gateway gets the certificates from the secret discovery service (SDS) built into the istio-agent process that’s used to start the istio-proxy.
 # SDS is a dynamic API that should automatically propagate the updates. The same is true for service proxies.
 #You can check the status of certificates delivered via SDS with the following com- mand:
 #istioctl pc secret -n istio-system deploy/istio-ingressgateway
 #Note that if you don’t see the new certificate configuration take effect, you may wish to “bounce” the istio-ingressgateway Pod:
 #kubectl delete po -n istio-system -l app=istio-ingressgateway


#4.3.4 Serving multiple virtual hosts with TLS

#kubectl create -n istio-system secret tls catalog-credential \
#--key ch4/certs2/3_application/private/catalog.istioinaction.io.key.pem  --cert ch4/certs2/3_application/certs/catalog.istioinaction.io.cert.pem

 kubectl cp -n default  ch4/certs2/3_application/private/catalog.istioinaction.io.key.pem vault-0:tmp/catalog.istioinaction.io.key.pem
 kubectl cp -n default  ch4/certs2/3_application/certs/catalog.istioinaction.io.cert.pem vault-0:tmp/catalog.istioinaction.io.cert.pem
 kubectl exec -n default --stdin=true --tty=true vault-0 -- /bin/sh

######################in vault-0##########################
vault kv put kvv2/catalog-credential  tls.crt=@/tmp/catalog.istioinaction.io.cert.pem tls.key=@/tmp/catalog.istioinaction.io.key.pem
vault kv get kvv2/catalog-credential
######################in vault-0##########################
kubectl apply -f catalog-credential-tls.yaml
kubectl describe -n istio-system secrets/catalog-credential
kubectl get secret -n istio-system  catalog-credential -o jsonpath='{.data}' | jq -r  '."tls.crt"' | base64 -D
kubectl get secret -n istio-system  catalog-credential -o jsonpath='{.data}' | jq -r  '."tls.key"' | base64 -D

#configure gateway to serve multiple tls hosts (webapp & catalog)
kubectl apply -f ch4/coolstore-gw-multi-tls.yaml

#we need to add a VirtualService resource for the catalog service we’ll expose through this ingress gateway
kubectl apply -f ch4/catalog-vs.yaml

#call webapp via istio-ingress
curl -H "Host: webapp.istioinaction.io" https://webapp.istioinaction.io:443/api/catalog \
--cacert ch4/certs/2_intermediate/certs/ca-chain.cert.pem  --resolve webapp.istioinaction.io:443:$LB_IP

#call catalog via istio-ingress
curl -H "Host: catalog.istioinaction.io" https://catalog.istioinaction.io:443/items \
--cacert ch4/certs2/2_intermediate/certs/ca-chain.cert.pem  --resolve catalog.istioinaction.io:443:$LB_IP

#wonder how the Istio ingress gateway knows which certificate to present, depending on who’s calling.
# There’s only a single port opened for these connections: how does it know which ser- vice the client is trying to access and which certificate corresponds with that service?
# The answer lies in an extension to TLS called Server Name Indication (SNI).
# Basically, when an HTTPS connection is created, the client first identifies which service it’s try- ing to reach using the ClientHello part of the TLS handshake.
# Istio’s gateway (Envoy, specifically) implements SNI on TLS, which is how it can present the correct cert and route to the correct service.