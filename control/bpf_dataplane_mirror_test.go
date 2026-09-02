//go:build !dae_stub_ebpf

package control

import (
	"reflect"
	"testing"
)

func TestDataplaneProgramsAndMapsComplete(t *testing.T) {
	assertDataplaneMirrorComplete(
		t,
		"program",
		reflect.TypeOf(bpfPrograms{}),
		reflect.TypeOf(bpfDataplanePrograms{}),
		tcpRelayOffloadPrograms,
	)
	assertDataplaneMirrorComplete(
		t,
		"map",
		reflect.TypeOf(bpfMaps{}),
		reflect.TypeOf(bpfDataplaneMaps{}),
		tcpRelayOffloadMaps,
	)
}

func TestAssignDataplaneToBpfCopiesMandatoryObjects(t *testing.T) {
	dataplane := new(bpfDataplane)
	populatePointerFields(reflect.ValueOf(&dataplane.bpfDataplanePrograms).Elem())
	populatePointerFields(reflect.ValueOf(&dataplane.bpfDataplaneMaps).Elem())

	objects := new(bpfObjects)
	assignDataplaneToBpf(objects, dataplane)
	assertPointerFieldsEqual(t, "program", reflect.ValueOf(&dataplane.bpfDataplanePrograms).Elem(), reflect.ValueOf(&objects.bpfPrograms).Elem())
	assertPointerFieldsEqual(t, "map", reflect.ValueOf(&dataplane.bpfDataplaneMaps).Elem(), reflect.ValueOf(&objects.bpfMaps).Elem())
}

func populatePointerFields(value reflect.Value) {
	for i := 0; i < value.NumField(); i++ {
		value.Field(i).Set(reflect.New(value.Field(i).Type().Elem()))
	}
}

func assertPointerFieldsEqual(t *testing.T, objectKind string, source, destination reflect.Value) {
	t.Helper()
	for i := 0; i < source.NumField(); i++ {
		field := source.Type().Field(i)
		got := destination.FieldByName(field.Name)
		if !got.IsValid() {
			t.Errorf("canonical BPF objects missing %s field %q", objectKind, field.Name)
			continue
		}
		if got.Pointer() != source.Field(i).Pointer() {
			t.Errorf("canonical BPF objects did not receive %s %q", objectKind, field.Tag.Get("ebpf"))
		}
	}
}

func assertDataplaneMirrorComplete(t *testing.T, objectKind string, generated, mandatory reflect.Type, optIn []string) {
	t.Helper()
	want := ebpfTaggedFields(generated)
	for _, name := range optIn {
		delete(want, name)
	}
	got := ebpfTaggedFields(mandatory)
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("mandatory dataplane missing %s %q", objectKind, name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("mandatory dataplane has unexpected %s %q", objectKind, name)
		}
	}
}

func ebpfTaggedFields(typ reflect.Type) map[string]struct{} {
	fields := make(map[string]struct{}, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Tag.Get("ebpf"); name != "" {
			fields[name] = struct{}{}
		}
	}
	return fields
}
