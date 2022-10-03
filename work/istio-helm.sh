 minikube delete && minikube start --kubernetes-version=v1.24.0 --memory=8g --cpus=4  --bootstrapper=kubeadm --extra-config=kubelet.authentication-token-webhook=true --extra-config=kubelet.authorization-mode=Webhook --extra-config=scheduler.bind-address=0.0.0.0 --extra-config=controller-manager.bind-address=0.0.0.0
minikube addons enable metrics-server

helm repo add istio https://istio-release.storage.googleapis.com/charts
helm repo update

kubectl create namespace istio-system
helm install istio-base istio/base -n istio-system
helm install istiod istio/istiod -n istio-system

kubectl create namespace istio-ingress
kubectl label namespace istio-ingress istio-injection=enabled



  helm repo add metallb https://metallb.github.io/metallb
  helm install metallb metallb/metallb


 cat work/metallb-adress-pool.yaml | sed "s@1.1.1.1@"$(minikube ip)"@" | kubectl diff  -f -

 cat work/metallb-adress-pool.yaml | sed "s@1.1.1.1@"$(minikube ip)"@" | kubectl apply  -f -

#we need metallb to autofill  EXTERNAL-IP  of service/istio-ingress
helm install istio-ingress istio/gateway -n istio-ingress
