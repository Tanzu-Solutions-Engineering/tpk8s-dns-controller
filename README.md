# TPK8s DNS

This repo provides a way to add support for many different DNS providers to Tanzu Platform. This is not a Tanzu officially supported method, it falls under the "bring your own DNS provider" category. 



# How it works

This is a wrapper around the OSS project [external-dns](https://github.com/kubernetes-sigs/external-dns/). This allows for DNS(GSLB) entries to be created using any of the external DNS providers using domain bindings as a source. This works by deploying external-dns as a capabilty and configuring it for whichever provider is required, in the config it is also set to only watch CRDs this means it will not watch services, ingress etc. the second component of this is a controller that runs in a space and requires the external-dns capability. this controller watches spaces for domain bindings and creates the `DnsEndpoint` CRs in the space based on those domain bindings. Those CRs are then watched by external-dns and it handles creating/updating/deleting the entries in the provider.

# Setup

## Setup the custom capability

**IMPORTANT: this is only meant to be used in a space with 1 replica and with a cluster group that only has 1 cluster, see more details in the FAQ**

Due to limitations in TPK8s today in order to add a custom package repo that contains custom capabilties a workaround is needed. These instructions outline that workaround. This workaround is only done once by the platform engineer, once the repo is added everything can be done through TPK8S normally. This will need to be done per cluster group.This workaround will allow for the pkgr to automatcally be installed on the clustergroup, this works around the lack of package repo syncing today and prevents the user from having to manually create pkgrs on indiviual clusters. The workaround does the following:

* adds the package repo and secret to TPK8s project
* adds the package repo and secret to the tpk8s cluster group

### Configure the tpk8s project with the custom repo

This sets up the the project to have access to the custom pkgr so that it will show up in the UI when looking for capabilties

1. add the package repo and secret to the project
```bash
tanzu project use <your-proj>
export KUBECONFIG=~/.config/tanzu/kube/config
kubectl apply -f tpk8s-resources/tpk8s-dns-repo.yml

```

### Configure the cluster group with the pkgr

This is needed becuase we need the cluster group to have access to to the pkgr. becuase the pkgr is private we need to sync a secret out to the unerlying clusters.

** make sure you cluster group only contains 1 cluster**

1. add pkgr and secret to the cluster group

```bash
tanzu ops clustergroup use <your-cg>
export KUBECONFIG=~/.config/tanzu/kube/config
kubectl apply -f tpk8s-resources/tpk8s-dns-repo.yml

```

## Deploy the capability

### template the values file with the secret details

in this example we will use azure. full steps found [here](https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/azure.md#service-principal)

copy the values-example.yml to capability-values.yml and update the contents. This values file is made to allow any fo the supported providers in the format shown [here](https://github.com/bitnami/charts/blob/main/bitnami/external-dns/values.yaml) and [here](https://github.com/bitnami/charts/blob/main/bitnami/external-dns/values.yaml#L302) with azure as the exmaple.then run the below command

```bash
tanzu ops clustergroup use <your-cg>
export KUBECONFIG=~/.config/tanzu/kube/config
 ytt -f templated-resources/external-dns-values.yml --data-values-file capability-values.yml  | kubectl apply -f- 
```

### Deploying the Capability

This can be done through the UI or the api. The steps below use the cli/api so that they can eb easily reproduced. This assumes you already have an availability target.

1. install the capability on the cluster group

```bash
tanzu ops clustergroup use <your-cg>
export KUBECONFIG=~/.config/tanzu/kube/config
k apply -f tpk8s-resources/external-dns-values.yml
k apply -f tpk8s-resources/dns-capability.yml
```


## Deploy the controller

### Create the space and profile

1. create a profile for the tpk8s-dns controller

```bash
tanzu project use <your-project>
export KUBECONFIG=~/.config/tanzu/kube/config
k apply -f tpk8s-resources/profile.yml
```

2. create a space using the profile. you will need to update the availability target in the yaml below as well as any profiles you need
```bash
tanzu project use <your-project>
export KUBECONFIG=~/.config/tanzu/kube/config
k apply -f tpk8s-resources/space.yml
```
3. add egress
```bash
tanzu space use your-space
export KUBECONFIG=~/.config/tanzu/kube/config
k apply -f tpk8s-resources/egress.yml
```


## Deploying in Tanzu Platform for K8s

This section outline how to deploy this as a part of a space in the platform. This is the recommended approach for running this.

###  Deploy the controller to a space


1. connect to your project and the space that was previsouly created
```bash
tanzu project use <project>
tanzu space use tpk8s-dns-controller-space
```
2. copy the `templated-resources/secret-example.yml` into the `.tanzu/config` directory and rename it `secret.yml`
3. Update all of the values in the `secret.yml` 
4. `tanzu deploy`

### Validating it works

you can check the logs on the controller pod in the cluster to make sure it is working along with the external-dns logs.

# FAQ

## Why can I only use this with 1 replica and 1 cluster?

This is due to a limitation with external dns and the way TPk8s expects to work. external DNS uses a txt-owner-id to detrmine which records it owns. wehn deployed into a cluster group as a capability this owner is the same between clusters. this means every cluster ijn the cluster group is trying to update the same domain. when a cluster is running external DNS but does not have a space replica on it, it will think there are no DNS entries and remove them. Thsi will create a constant conflict between clusters tryign to delete and update records. You could have the same number of space replicas as clusters and it would not create this issue, however that could lead to other issues if a space re-schedule, etc. for this reason the safest way to deploy this is to ensure the cluster group only has 1 cluster and the space only has 1 replica.

## What if I need to replace the cluster it's running on?

This takes a careful appropach in order to not cause DNS downtime. First edit your values file for the external DNS capability and set the policy to `upsert-only` this will prevent records from being deleted. Next create a new cluster in your cluster group, becuase it's in upsert only mode the new cluster's external dns controller will not try to delete records. next scale your space to 2 replicas. at this point both clusters should be sycning the records and there should be no errors. you can now cordon and drain the old cluster. lastly update the policy back to `sync`.

## how does this work with multiple space replicas?

This is an underlying limitation of external-dns. It does not support running multiple replicas therefore it is not recommended to run this with multiple replicas.

## How does this handle space re-scheduling?

It is recommended to run this with `rollingUpdate` as the strategy for spaces. If this is deployed with external dns using `policy: sync` there is a possibility of having a record deleted and the recreate cuasing minimal downtime. If this is run with `policy: upsert-only` it will not delete records so there will not be an issue of potetnial record recreation, however records will not be deleted and deletes will need to be handled manually. 



# Known issues

# Cross cloud k8s provider DNS issues

Certain cloud providers like EKS use hostnames for their address when creating a service type LB. This is an issue becuase it is not possible to create a single record that has hostnames and IP addresses. in some DNS providers this can we worked around by using CNAMEs , however some providers do not allow multiple entries with the same DNS fqdn(Azure for exmaple). due to this limitation and lack of consistency between providers this controller can only work aross providers that use the same underlying format for thier addresses. mostly this is an issue with combining EKS and any other provider in the same space. If you are using EKS it's better to use the native route53 integration.