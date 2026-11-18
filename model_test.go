package gosslyze

import (
	"fmt"
	"testing"
	"time"
)

func TestUtcTime_UnmarshalJSON(t *testing.T) {
	type fields struct {
		String string
		Time   time.Time
	}
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Without timezone",
			data:    []byte("2024-07-31T10:36:00"),
			wantErr: false,
		},
		{
			name:    "With timezone",
			data:    []byte("2024-07-31T10:36:00Z"),
			wantErr: false,
		},
		{
			name:    "With timezone and milliseconds",
			data:    []byte("2024-07-31T10:36:00.8111Z"),
			wantErr: false,
		},
		{
			name:    "With timezone and milliseconds short",
			data:    []byte("2024-07-31T10:36:00.8Z"),
			wantErr: false,
		},
		{
			name:    "With full details",
			data:    []byte("2024-07-31T10:36:00.8111-02:00"),
			wantErr: false,
		},
		{
			name:    "With full details milliseconds short",
			data:    []byte("2024-07-31T10:36:00.8-02:00"),
			wantErr: false,
		},
		{
			name:    "Invalid 1",
			data:    []byte("2024-07 10:36:00"),
			wantErr: true,
		},
		{
			name:    "Invalid 2",
			data:    []byte("2024-07T10:36:00.8111Z"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ut := &UtcTime{}
			fmt.Println(string(tt.data))
			if err := ut.UnmarshalJSON(tt.data); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Println(ut.Time)
			fmt.Println()
		})
	}
}
