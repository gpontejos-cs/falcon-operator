package v1alpha1

import "testing"

func strPtr(s string) *string { return &s }

func TestFalconAdmissionGetClusterName(t *testing.T) {
	tests := []struct {
		name            string
		specClusterName *string
		want            *string
	}{
		{
			name:            "top-level ClusterName set",
			specClusterName: strPtr("my-cluster"),
			want:            strPtr("my-cluster"),
		},
		{
			name:            "top-level ClusterName unset",
			specClusterName: nil,
			want:            nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &FalconAdmission{}
			ac.Spec.ClusterName = tt.specClusterName
			got := ac.GetClusterName()
			if tt.want == nil && got != nil {
				t.Errorf("GetClusterName() = %q, want nil", *got)
			}
			if tt.want != nil && (got == nil || *got != *tt.want) {
				t.Errorf("GetClusterName() = %v, want %q", got, *tt.want)
			}
		})
	}
}

func TestFalconClusterGuardGetClusterName(t *testing.T) {
	tests := []struct {
		name                    string
		admissionConfigCluster  *string
		want                    *string
	}{
		{
			name:                   "admissionConfig ClusterName set",
			admissionConfigCluster: strPtr("my-cluster"),
			want:                   strPtr("my-cluster"),
		},
		{
			name:                   "admissionConfig ClusterName unset",
			admissionConfigCluster: nil,
			want:                   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fcg := &FalconClusterGuard{}
			fcg.Spec.AdmissionConfig.ClusterName = tt.admissionConfigCluster
			got := fcg.GetClusterName()
			if tt.want == nil && got != nil {
				t.Errorf("GetClusterName() = %q, want nil", *got)
			}
			if tt.want != nil && (got == nil || *got != *tt.want) {
				t.Errorf("GetClusterName() = %v, want %q", got, *tt.want)
			}
		})
	}
}
