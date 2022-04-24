// Code generated by entc, DO NOT EDIT.

package db

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/dexidp/dex/storage/ent/db/password"
	"github.com/dexidp/dex/storage/ent/db/predicate"
)

// PasswordUpdate is the builder for updating Password entities.
type PasswordUpdate struct {
	config
	hooks    []Hook
	mutation *PasswordMutation
}

// Where appends a list predicates to the PasswordUpdate builder.
func (pu *PasswordUpdate) Where(ps ...predicate.Password) *PasswordUpdate {
	pu.mutation.Where(ps...)
	return pu
}

// SetEmail sets the "email" field.
func (pu *PasswordUpdate) SetEmail(s string) *PasswordUpdate {
	pu.mutation.SetEmail(s)
	return pu
}

// SetHash sets the "hash" field.
func (pu *PasswordUpdate) SetHash(b []byte) *PasswordUpdate {
	pu.mutation.SetHash(b)
	return pu
}

// SetUsername sets the "username" field.
func (pu *PasswordUpdate) SetUsername(s string) *PasswordUpdate {
	pu.mutation.SetUsername(s)
	return pu
}

// SetUserID sets the "user_id" field.
func (pu *PasswordUpdate) SetUserID(s string) *PasswordUpdate {
	pu.mutation.SetUserID(s)
	return pu
}

// Mutation returns the PasswordMutation object of the builder.
func (pu *PasswordUpdate) Mutation() *PasswordMutation {
	return pu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (pu *PasswordUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(pu.hooks) == 0 {
		if err = pu.check(); err != nil {
			return 0, err
		}
		affected, err = pu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*PasswordMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = pu.check(); err != nil {
				return 0, err
			}
			pu.mutation = mutation
			affected, err = pu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(pu.hooks) - 1; i >= 0; i-- {
			if pu.hooks[i] == nil {
				return 0, fmt.Errorf("db: uninitialized hook (forgotten import db/runtime?)")
			}
			mut = pu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, pu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (pu *PasswordUpdate) SaveX(ctx context.Context) int {
	affected, err := pu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (pu *PasswordUpdate) Exec(ctx context.Context) error {
	_, err := pu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (pu *PasswordUpdate) ExecX(ctx context.Context) {
	if err := pu.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (pu *PasswordUpdate) check() error {
	if v, ok := pu.mutation.Email(); ok {
		if err := password.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`db: validator failed for field "Password.email": %w`, err)}
		}
	}
	if v, ok := pu.mutation.Username(); ok {
		if err := password.UsernameValidator(v); err != nil {
			return &ValidationError{Name: "username", err: fmt.Errorf(`db: validator failed for field "Password.username": %w`, err)}
		}
	}
	if v, ok := pu.mutation.UserID(); ok {
		if err := password.UserIDValidator(v); err != nil {
			return &ValidationError{Name: "user_id", err: fmt.Errorf(`db: validator failed for field "Password.user_id": %w`, err)}
		}
	}
	return nil
}

func (pu *PasswordUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   password.Table,
			Columns: password.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: password.FieldID,
			},
		},
	}
	if ps := pu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := pu.mutation.Email(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldEmail,
		})
	}
	if value, ok := pu.mutation.Hash(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: password.FieldHash,
		})
	}
	if value, ok := pu.mutation.Username(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldUsername,
		})
	}
	if value, ok := pu.mutation.UserID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldUserID,
		})
	}
	if n, err = sqlgraph.UpdateNodes(ctx, pu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{password.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{err.Error(), err}
		}
		return 0, err
	}
	return n, nil
}

// PasswordUpdateOne is the builder for updating a single Password entity.
type PasswordUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *PasswordMutation
}

// SetEmail sets the "email" field.
func (puo *PasswordUpdateOne) SetEmail(s string) *PasswordUpdateOne {
	puo.mutation.SetEmail(s)
	return puo
}

// SetHash sets the "hash" field.
func (puo *PasswordUpdateOne) SetHash(b []byte) *PasswordUpdateOne {
	puo.mutation.SetHash(b)
	return puo
}

// SetUsername sets the "username" field.
func (puo *PasswordUpdateOne) SetUsername(s string) *PasswordUpdateOne {
	puo.mutation.SetUsername(s)
	return puo
}

// SetUserID sets the "user_id" field.
func (puo *PasswordUpdateOne) SetUserID(s string) *PasswordUpdateOne {
	puo.mutation.SetUserID(s)
	return puo
}

// Mutation returns the PasswordMutation object of the builder.
func (puo *PasswordUpdateOne) Mutation() *PasswordMutation {
	return puo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (puo *PasswordUpdateOne) Select(field string, fields ...string) *PasswordUpdateOne {
	puo.fields = append([]string{field}, fields...)
	return puo
}

// Save executes the query and returns the updated Password entity.
func (puo *PasswordUpdateOne) Save(ctx context.Context) (*Password, error) {
	var (
		err  error
		node *Password
	)
	if len(puo.hooks) == 0 {
		if err = puo.check(); err != nil {
			return nil, err
		}
		node, err = puo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*PasswordMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = puo.check(); err != nil {
				return nil, err
			}
			puo.mutation = mutation
			node, err = puo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(puo.hooks) - 1; i >= 0; i-- {
			if puo.hooks[i] == nil {
				return nil, fmt.Errorf("db: uninitialized hook (forgotten import db/runtime?)")
			}
			mut = puo.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, puo.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (puo *PasswordUpdateOne) SaveX(ctx context.Context) *Password {
	node, err := puo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (puo *PasswordUpdateOne) Exec(ctx context.Context) error {
	_, err := puo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (puo *PasswordUpdateOne) ExecX(ctx context.Context) {
	if err := puo.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (puo *PasswordUpdateOne) check() error {
	if v, ok := puo.mutation.Email(); ok {
		if err := password.EmailValidator(v); err != nil {
			return &ValidationError{Name: "email", err: fmt.Errorf(`db: validator failed for field "Password.email": %w`, err)}
		}
	}
	if v, ok := puo.mutation.Username(); ok {
		if err := password.UsernameValidator(v); err != nil {
			return &ValidationError{Name: "username", err: fmt.Errorf(`db: validator failed for field "Password.username": %w`, err)}
		}
	}
	if v, ok := puo.mutation.UserID(); ok {
		if err := password.UserIDValidator(v); err != nil {
			return &ValidationError{Name: "user_id", err: fmt.Errorf(`db: validator failed for field "Password.user_id": %w`, err)}
		}
	}
	return nil
}

func (puo *PasswordUpdateOne) sqlSave(ctx context.Context) (_node *Password, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   password.Table,
			Columns: password.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: password.FieldID,
			},
		},
	}
	id, ok := puo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`db: missing "Password.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := puo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, password.FieldID)
		for _, f := range fields {
			if !password.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("db: invalid field %q for query", f)}
			}
			if f != password.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := puo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := puo.mutation.Email(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldEmail,
		})
	}
	if value, ok := puo.mutation.Hash(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeBytes,
			Value:  value,
			Column: password.FieldHash,
		})
	}
	if value, ok := puo.mutation.Username(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldUsername,
		})
	}
	if value, ok := puo.mutation.UserID(); ok {
		_spec.Fields.Set = append(_spec.Fields.Set, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: password.FieldUserID,
		})
	}
	_node = &Password{config: puo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, puo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{password.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{err.Error(), err}
		}
		return nil, err
	}
	return _node, nil
}
