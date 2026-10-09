package tests

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/navidrome/navidrome/model"
)

func CreateMockUserRepo() *MockedUserRepo {
	return &MockedUserRepo{
		Data:          map[string]*model.User{},
		UserLibraries: map[string][]int{},
	}
}

type MockedUserRepo struct {
	model.UserRepository
	mu            sync.RWMutex
	Error         error
	Data          map[string]*model.User
	UserLibraries map[string][]int // userID -> libraryIDs
}

func (u *MockedUserRepo) CountAll(_ context.Context, qo ...model.QueryOptions) (int64, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return 0, u.Error
	}
	return int64(len(u.Data)), nil
}

func (u *MockedUserRepo) Put(_ context.Context, usr *model.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	if usr.ID == "" {
		usr.ID = base64.StdEncoding.EncodeToString([]byte(usr.UserName))
	}
	usr.Password = usr.NewPassword
	u.Data[strings.ToLower(usr.UserName)] = usr
	return nil
}

func (u *MockedUserRepo) FindByUsername(_ context.Context, username string) (*model.User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return nil, u.Error
	}
	usr, ok := u.Data[strings.ToLower(username)]
	if !ok {
		return nil, model.ErrNotFound
	}
	copy := *usr
	return &copy, nil
}

func (u *MockedUserRepo) FindByUsernameWithPassword(ctx context.Context, username string) (*model.User, error) {
	return u.FindByUsername(ctx, username)
}

func (u *MockedUserRepo) FindFirstAdmin(_ context.Context) (*model.User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return nil, u.Error
	}
	for _, usr := range u.Data {
		if usr.IsAdmin {
			return usr, nil
		}
	}
	return nil, model.ErrNotFound
}

func (u *MockedUserRepo) Get(_ context.Context, id string) (*model.User, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return nil, u.Error
	}
	for _, usr := range u.Data {
		if usr.ID == id {
			return usr, nil
		}
	}
	return nil, model.ErrNotFound
}

func (u *MockedUserRepo) GetAll(_ context.Context, options ...model.QueryOptions) (model.Users, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return nil, u.Error
	}
	var users model.Users
	for _, usr := range u.Data {
		users = append(users, *usr)
	}
	return users, nil
}

func (u *MockedUserRepo) UpdateLastLoginAt(_ context.Context, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, usr := range u.Data {
		if usr.ID == id {
			usr.LastLoginAt = new(time.Now())
			return nil
		}
	}
	return u.Error
}

func (u *MockedUserRepo) UpdateLastAccessAt(_ context.Context, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, usr := range u.Data {
		if usr.ID == id {
			usr.LastAccessAt = new(time.Now())
			return nil
		}
	}
	return u.Error
}

func (u *MockedUserRepo) UpdateLDAPAdmin(ctx context.Context, id string, isAdmin bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	for _, usr := range u.Data {
		if usr.ID == id {
			if !usr.IsLDAP() {
				return model.ErrNotFound
			}
			usr.IsAdmin = isAdmin
			return nil
		}
	}
	return model.ErrNotFound
}

func (u *MockedUserRepo) SyncLDAPLogin(_ context.Context, synced *model.User, updateAdmin bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	for _, usr := range u.Data {
		if usr.ID != synced.ID {
			continue
		}
		usr.Name = synced.Name
		usr.Email = synced.Email
		usr.AuthType = model.AuthTypeLDAP
		if updateAdmin {
			usr.IsAdmin = synced.IsAdmin
		}
		usr.UpdatedAt = time.Now()
		return nil
	}
	return model.ErrNotFound
}

func (u *MockedUserRepo) ClearPassword(_ context.Context, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	for _, usr := range u.Data {
		if usr.ID == id {
			usr.Password = ""
			usr.NewPassword = ""
			return nil
		}
	}
	return model.ErrNotFound
}

// Library association methods - mock implementations

func (u *MockedUserRepo) GetUserLibraries(_ context.Context, userID string) (model.Libraries, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	if u.Error != nil {
		return nil, u.Error
	}
	libraryIDs, exists := u.UserLibraries[userID]
	if !exists {
		return model.Libraries{}, nil
	}

	// Mock: Create libraries based on IDs
	var libraries model.Libraries
	for _, id := range libraryIDs {
		libraries = append(libraries, model.Library{
			ID:   id,
			Name: fmt.Sprintf("Test Library %d", id),
			Path: fmt.Sprintf("/music/library%d", id),
		})
	}
	return libraries, nil
}

func (u *MockedUserRepo) SetUserLibraries(_ context.Context, userID string, libraryIDs []int) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	if u.UserLibraries == nil {
		u.UserLibraries = make(map[string][]int)
	}
	u.UserLibraries[userID] = libraryIDs
	return nil
}

func (u *MockedUserRepo) Delete(_ context.Context, ids ...string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Error != nil {
		return u.Error
	}
	for _, id := range ids {
		if err := u.deleteOne(id); err != nil {
			return err
		}
	}
	return nil
}

func (u *MockedUserRepo) deleteOne(id string) error {
	for key, usr := range u.Data {
		if usr.ID == id {
			delete(u.Data, key)
			delete(u.UserLibraries, id)
			return nil
		}
	}
	return model.ErrNotFound
}

func (u *MockedUserRepo) Save(ctx context.Context, usr *model.User) (string, error) {
	if err := u.Put(ctx, usr); err != nil {
		return "", err
	}
	return usr.ID, nil
}

func (u *MockedUserRepo) Update(ctx context.Context, id string, entity model.User, _ ...string) error {
	entity.ID = id
	// Mirror userRepository.Update: auth_type is preserved from the
	// existing row, never taken from the incoming payload.
	u.mu.RLock()
	for _, existing := range u.Data {
		if existing.ID == id {
			entity.AuthType = existing.AuthType
			break
		}
	}
	u.mu.RUnlock()
	return u.Put(ctx, &entity)
}
