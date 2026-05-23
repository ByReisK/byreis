package tui

import "github.com/charmbracelet/huh"

// SubmitForm wraps the huh form that collects a masked secret value from the
// contributor. It is the primary interactive input surface for the submit
// screen. The form is constructed fresh per submit invocation so no plaintext
// lingers across runs.
//
// The zero value is not usable; construct via newSubmitForm.
type SubmitForm struct {
	inner *huh.Form
	value string
}

// newSubmitForm constructs a SubmitForm with a single masked input field.
// The field is pre-labelled with keyName so the contributor sees which secret
// they are entering. The value is populated by Run; callers must zeroize it
// after passing it to the use-case.
func newSubmitForm(keyName string) *SubmitForm {
	var value string
	inner := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(keyName).
				EchoMode(huh.EchoModePassword).
				Value(&value),
		),
	)
	return &SubmitForm{inner: inner, value: value}
}

// Run executes the form, blocking until the contributor completes or cancels
// the input. It returns the entered value. Callers are responsible for
// zeroizing the returned string after use.
func (f *SubmitForm) Run() (string, error) {
	if err := f.inner.Run(); err != nil {
		return "", err
	}
	return f.value, nil
}
