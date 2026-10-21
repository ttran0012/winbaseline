//go:build windows

package collect

// Group Policy settings override the local firewall settings, so the policy
// location is checked first.
var firewallKeys = map[string][2]string{
	"domain":  {`SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`},
	"private": {`SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`},
	"public":  {`SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`},
}

// firewallProfile reads the effective EnableFirewall state (1 on, 0 off) for a
// profile. Text records whether the value came from Group Policy or the local
// setting.
func (c *Collector) firewallProfile(profile string) Reading {
	keys := firewallKeys[profile]
	if r := c.registryDWORD(keys[0], "EnableFirewall"); r.Err != nil || r.Present {
		r.Text = "group policy"
		return r
	}
	r := c.registryDWORD(keys[1], "EnableFirewall")
	r.Text = "local setting"
	return r
}
