package validation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"

	dErrors "credo/pkg/domain-errors"
	s "credo/pkg/string"
)

var defaultValidator = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	_ = v.RegisterValidation("notblank", func(fl validator.FieldLevel) bool {
		return strings.TrimSpace(fl.Field().String()) != ""
	})
	return v
}

// Validate validates a struct using the default validator and returns a domain error
func Validate(req any) error {
	if err := defaultValidator.Struct(req); err != nil {
		return dErrors.New(dErrors.CodeValidation, ErrorMessage(err))
	}
	return nil
}

// ErrorMessage converts a validator error into a human-readable message
func ErrorMessage(err error) string {
	var validationErrs validator.ValidationErrors
	if !errors.As(err, &validationErrs) || len(validationErrs) == 0 {
		return "invalid request body"
	}

	fe := validationErrs[0]
	fieldName := fe.Field()
	if fieldName == "" {
		fieldName = fe.StructField()
	}
	field := s.ToSnakeCase(fieldName)

	switch fe.ActualTag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "email":
		return fmt.Sprintf("%s must be a valid email", field)
	case "url":
		return fmt.Sprintf("%s must be a valid url", field)
	case "uuid":
		return fmt.Sprintf("%s must be a valid uuid", field)
	case "min":
		return fmt.Sprintf("%s must be at least %s", field, fe.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s", field, fe.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of [%s]", field, fe.Param())
	case "notblank":
		return fmt.Sprintf("%s must not be blank", field)
	default:
		if field == "" {
			return "invalid request body"
		}
		return fmt.Sprintf("%s is invalid", field)
	}
}
