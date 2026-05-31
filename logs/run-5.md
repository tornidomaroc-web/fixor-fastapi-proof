# Fixor local scan report

> This report is scoped to detection. Automated remediation is out of scope and not shown.

- Scanned path: `fixtures/real-shape/fastapi-saas`
- Total files scanned: 7
- Files with findings: 3
- Total findings: 6
- Severity breakdown: critical=6, high=0, medium=0

## app/routers/admin.py

### auth_bypass_risk — critical (confidence: high)

- File: `app/routers/admin.py`:21
- Description: The `POST /users/{user_id}/role` route performs a highly sensitive admin action (changing a user's role and potentially granting superuser privileges) but has NO authentication or authorization dependency. The `current_user: CurrentUser` parameter injects the current user but does NOT enforce any role/permission check — there is no inline check verifying the caller is a superuser or admin before mutating the user record. In contrast, the sibling `GET /stats` route on the same router explicitly uses `dependencies=[Depends(get_current_active_superuser)]`, confirming that admin gating is the intended pattern here and was simply omitted from this route.

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
- Description: The `POST /users/{user_id}/role` route performs a highly privileged administrative action (changing a user's role and potentially granting superuser status) but has NO admin gate — it only uses `CurrentUser` (a plain authentication dependency, not an admin-authorization dependency), while the sibling `GET /stats` route on the same router explicitly requires `Depends(get_current_active_superuser)`. Any authenticated non-admin user can call this endpoint to promote themselves or others to admin.

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
- Description: The `DELETE /{user_id}` route performs a destructive action (deleting any user by ID) and has NO authentication or authorization dependency — its only parameter is `Depends(get_session)`, a non-auth DB session dependency. Sibling routes `GET /me` and `PATCH /me` both use `CurrentUser` (an auth-suggesting dependency from `app.auth`) as a guard, making it clear that auth is intentionally applied on this router, yet it is absent on the delete route.

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
- Description: The request-derived `user_id` flows directly into `session.get(User, user_id)` with no ownership filter in the query and no post-fetch ownership check — any authenticated (or even unauthenticated) caller can delete any user's record by supplying an arbitrary `user_id`. Although `CurrentUser` is imported, it is not injected as a dependency in `delete_user`, so there is no session-based identity check whatsoever on this endpoint.

```
    user = session.get(User, user_id)
    if user:
        session.delete(user)
        session.commit()
    return {"deleted": user_id}
```

---
