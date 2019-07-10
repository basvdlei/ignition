// Copyright 2021 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smartos

import (
	"reflect"
	"testing"
)

func assertInt(t *testing.T, want, got int) {
	if want != got {
		t.Errorf("integers do not matchs:\n\nwant: %d\ngot : %d\n",
			want, got)
	}
}

func assertString(t *testing.T, want, got string) {
	if want != got {
		t.Errorf("strings do not matchs:\n\nwant: %s\ngot : %s\n",
			want, got)
	}
}

func assertFrame(t *testing.T, want, got Frame) {
	if want.BodyLength != got.BodyLength ||
		want.BodyChecksum != got.BodyChecksum ||
		want.Body.Code != got.Body.Code ||
		want.Body.RequestID != got.Body.RequestID ||
		!reflect.DeepEqual(want.Body.Payload, got.Body.Payload) {
		t.Errorf("frames do not match:\n\nwant: %+v\n\ngot : %+v\n",
			want, got)
	}
}

var frametests = []struct {
	frame Frame
	text  string
}{
	{
		frame: Frame{
			BodyLength:   21,
			BodyChecksum: "265ae1d8",
			Body: Body{
				RequestID: 3696209431,
				Code:      "SUCCESS",
				Payload:   []byte("[]"),
			},
		},
		text: "V2 21 265ae1d8 dc4fae17 SUCCESS W10=\n",
	},
}

func TestFrameMarshal(t *testing.T) {
	for _, c := range frametests {
		text, err := c.frame.MarshalText()
		if err != nil {
			t.Error(err)
		}
		assertString(t, c.text, string(text))
	}
}

func TestFrameUnmarshal(t *testing.T) {
	for _, c := range frametests {
		var f Frame
		err := f.UnmarshalText([]byte(c.text))
		if err != nil {
			t.Error(err)
		}
		assertFrame(t, c.frame, f)
	}
}

func TestFrameParse(t *testing.T) {
	for _, c := range frametests {
		f := c.frame
		f.BodyLength = 0
		f.BodyChecksum = ""
		f.Parse()
		assertInt(t, c.frame.BodyLength, f.BodyLength)
		assertString(t, c.frame.BodyChecksum, f.BodyChecksum)
	}
}
