# Fixor local scan report

> This report is scoped to detection. Automated remediation is out of scope and not shown.

- Scanned path: `fixtures/real-shape/fastapi-saas`
- Total files scanned: 7
- Files with findings: 3
- Total findings: 7
- Severity breakdown: critical=7, high=0, medium=0

## app/routers/admin.py

### auth_bypass_risk — critical (confidence: high)

- File: `app/routers/admin.py`:21
- Description: The `POST /users/{user_id}/role` route performs a highly sensitive admin action (changing a user's role and potentially granting superuser privileges) but has NO authentication or authorization dependency. The `current_user: CurrentUser` parameter injects the current user but does NOT enforce any role/permission check — it is not an auth-gating dependency by name convention. The sibling route `GET /stats` explicitly uses `dependencies=[Depends(get_current_active_superuser)]`, confirming the pattern for gating admin routes is known and used in this file, yet it is absent from the role-assignment route.

```
@router.post("/users/{user_id}/role")
def set_user_role(
    user_id: int,
    role: str,
    current_user: CurrentUser,
    session: Annotated[Session, Depends(get_session)],
) -> User:
    user = session.get(User, user_id)
```

### admin_check_risk — critical (confidence: high)

- File: `app/routers/admin.py`:21
- Description: The `POST /users/{user_id}/role` route performs a highly privileged administrative action (changing a user's role and potentially granting superuser status) but has NO admin gate — it only uses `CurrentUser` (a plain authentication dependency) with no admin-suggesting dependency, no inline `is_superuser`/role check, and no `@admin_required` decorator. Meanwhile, the sibling `GET /stats` route on the same router is explicitly guarded with `Depends(get_current_active_superuser)`, making the missing gate on the role-change route a clear vulnerability.

```
@router.post("/users/{user_id}/role")
def set_user_role(
    user_id: int,
    role: str,
    current_user: CurrentUser,
    session: Annotated[Session, Depends(get_session)],
) -> User:
    user = session.get(User, user_id)
```

### idor_risk — critical (confidence: high)

- File: `app/routers/admin.py`:28
- Description: The `set_user_role` endpoint at `POST /users/{user_id}/role` accepts a request-derived `user_id` and directly fetches the `User` object via `session.get(User, user_id)` with no ownership filter and no post-fetch authorization check. Critically, unlike the `/stats` endpoint above it, this handler has **no** `dependencies=[Depends(get_current_active_superuser)]` guard — it only injects `CurrentUser` (a generic authenticated-user dependency), meaning any authenticated user can call this endpoint and promote any arbitrary user (including themselves) to admin by supplying any `user_id`.

```
    user = session.get(User, user_id)
    user.role = role
    if role == "admin":
        user.is_superuser = True
    session.add(user)
    session.commit()
    session.refresh(user)
    return user
```

---

## app/routers/items.py

### idor_risk — critical (confidence: high)

- File: `app/routers/items.py`:30
- Description: The request-derived `item_id` flows directly into `session.get(Item, item_id)` with no ownership filter in the query and no post-fetch ownership check (e.g., `if item.owner_id != current_user.id`). The `Item` model has an `owner_id` field (evidenced by its use in `list_own_items`), confirming this is an owned resource, yet any authenticated user can read any item by guessing its ID.

```
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@router.delete("/{item_id}")
def delete_item(
```

---

## app/routers/users.py

### auth_bypass_risk — critical (confidence: high)

- File: `app/routers/users.py`:32
- Description: The `DELETE /users/{user_id}` route performs a destructive action (deleting any user by ID) and has NO authentication or authorization dependency — its only parameter is `Depends(get_session)`, a non-auth DB session dependency. In contrast, sibling routes `GET /me` and `PATCH /me` both require `CurrentUser` (an auth-suggesting dependency from `app.auth`), confirming that auth gating is the established pattern on this router. The delete route is completely unguarded, allowing any unauthenticated caller to delete arbitrary users.

```
@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    user = session.get(User, user_id)
    if user:
        session.delete(user)
```

### admin_check_risk — critical (confidence: high)

- File: `app/routers/users.py`:32
- Description: The `DELETE /{user_id}` route performs a destructive administrative action (deleting any user by ID) but has NO authentication or admin authorization check — no `CurrentUser` dependency, no admin-suggesting `Depends(...)`, and no inline role/admin check in the body. Meanwhile, sibling routes (`GET /me`, `PATCH /me`) both require `CurrentUser` (authentication), making the missing guard on the delete route a clear anomaly. Any unauthenticated caller can delete arbitrary users.

```
@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    user = session.get(User, user_id)
    if user:
        session.delete(user)
```

### idor_risk — critical (confidence: high)

- File: `app/routers/users.py`:37
- Description: The request-derived `user_id` flows directly into `session.get(User, user_id)` with no ownership filter in the query and no post-fetch ownership check (e.g., comparing `user.id` to the authenticated `current_user.id`). The handler has no authentication dependency at all — `CurrentUser` is imported but not used as a parameter in `delete_user` — meaning any unauthenticated or authenticated caller can delete any user record by supplying an arbitrary `user_id`.

```
    user = session.get(User, user_id)
    if user:
        session.delete(user)
        session.commit()
    return {"deleted": user_id}
```

---
