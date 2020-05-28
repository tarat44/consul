// +build !consulent

package structs

import (
	"fmt"

	"github.com/hashicorp/consul/acl"
)

const (
	EnterpriseACLPolicyGlobalManagement = ""

	// aclPolicyTemplateServiceIdentity is the template used for synthesizing
	// policies for service identities.
	aclPolicyTemplateServiceIdentity = `
service "%[1]s" {
	policy = "write"
}
service "%[1]s-sidecar-proxy" {
	policy = "write"
}
service_prefix "" {
	policy = "read"
}
node_prefix "" {
	policy = "read"
}`

	aclPolicyTemplateNodeIdentity = `
node "%[1]s" {
	policy = "write"
}
service_prefix "" {
	policy = "read"
}`
)

type ACLAuthMethodEnterpriseFields struct{}

type ACLAuthMethodEnterpriseMeta struct{}

func (_ *ACLAuthMethodEnterpriseMeta) FillWithEnterpriseMeta(_ *EnterpriseMeta) {
	// do nothing
}

func (_ *ACLAuthMethodEnterpriseMeta) ToEnterpriseMeta() *EnterpriseMeta {
	return DefaultEnterpriseMeta()
}

func aclServiceIdentityRules(svc string, _ *EnterpriseMeta) string {
	return fmt.Sprintf(aclPolicyTemplateServiceIdentity, svc)
}

func (p *ACLPolicy) EnterprisePolicyMeta() *acl.EnterprisePolicyMeta {
	return nil
}

func (m *ACLAuthMethod) TargetEnterpriseMeta(_ *EnterpriseMeta) *EnterpriseMeta {
	return &m.EnterpriseMeta
}

func (t *ACLToken) NodeIdentityList() []*ACLNodeIdentity {
	if len(t.NodeIdentities) == 0 {
		return nil
	}

	out := make([]*ACLNodeIdentity, 0, len(t.NodeIdentities))
	for _, n := range t.NodeIdentities {
		out = append(out, n.Clone())
	}
	return out
}

func (r *ACLRole) NodeIdentityList() []*ACLNodeIdentity {
	if len(r.NodeIdentities) == 0 {
		return nil
	}

	out := make([]*ACLNodeIdentity, 0, len(r.NodeIdentities))
	for _, n := range r.NodeIdentities {
		out = append(out, n.Clone())
	}
	return out
}
