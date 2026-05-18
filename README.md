# Pug.Authorize

Multi-tenant role-based application object authorization framework.

![develop - build](https://github.com/NDWX/Authorized/workflows/develop%20-%20build/badge.svg?branch=develop) ![main - build and NuGet publish](https://github.com/NDWX/Authorized/workflows/main%20-%20build%20and%20NuGet%20publish/badge.svg?branch=main)

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) [![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized)

[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) [![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) 

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized)  [![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=NDWX_Authorized&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=NDWX_Authorized) 

## The Problem

Role-based access control at the application level often collapses into blunt role checks — either a user has a role or they don't. This breaks down when:

- Different users need different permissions on the same type of resource (e.g. one manager can edit a document another cannot)
- Resources are isolated across tenants and permissions must not leak between them
- A blanket role grant for an object type needs to be overridden with a denial for a specific instance
- Permission rules need to be configured at runtime by administrators rather than hard-coded at deploy time

## Solution

Pug.Authorize is an Access Control List (ACL) framework for .NET that attaches explicit `Allowed` or `Denied` entries to the tuple of *(subject, action, object, domain)*. It resolves authorization at runtime through a layered lookup:

1. Check the permission assigned to the subject for the **specific object**
2. If none, check the permission for the **object type** (all instances of that type)
3. If none, check the permission for the **action** regardless of object type
4. Accumulate permissions across all of the subject's roles (logical OR), where any explicit `Denied` overrides all grants

Context conditions on individual entries enable attribute-based checks (e.g. "only when the resource is in `pending` state").

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Subject** | A `Noun` (`Type` + `Identifier`) representing a user (`SubjectTypes.User`) or group/role (`SubjectTypes.Group`) |
| **Object** | A `NounQualifier` (`Domain` + `Type` + `Identifier`) identifying the resource being accessed |
| **Action** | A string naming the operation, e.g. `"READ"`, `"MODIFY"`, `"DELETE"` |
| **Permission** | `Permissions.Allowed`, `Permissions.Denied`, or `Permissions.None` |
| **Context** | Optional key/value conditions evaluated against runtime state before an ACE applies |
| **Purpose** | A namespace that scopes ACEs — one data store can serve multiple authorization concerns |
| **Domain** | Multi-tenancy scope; objects in different domains are fully isolated |

## Project Structure

| Package | Purpose |
|---------|---------|
| `Pug.Authorized.Common` | Core abstractions: `IAuthorized` interface and exception types |
| `Pug.Authorized` | Framework implementation (`Authorized`, `Options`, `DefaultIdentifierGenerator`) |
| `Pug.Authorized.DependencyInjection` | `IServiceCollection` extension (`AddAuthorized`) for ASP.NET Core / generic host |
| `Pug.Authorized.Data.Common` | `IAuthorizedDataStore` abstraction for the persistence layer |
| `Pug.Authorized.Data.SqlLite` | SQLite-backed `AuthorizationDataStore` implementation |
| `Pug.Authorized.WebApi` | ASP.NET Core Minimal API endpoints for ACL management over HTTP |

## Usage

### 1. Initialize the data store

Create the SQLite database before first use:

```csharp
AuthorizationDataStore.Create("authorizations.sqlite");
```

### 2. Register services

Pug.Authorize requires an `IPrincipalIdentityAccessor` (or `ISessionUserIdentityAccessor`) and an `IPrincipalRoleProvider` (or `IUserRoleProvider`) already registered in the container. Register the data store and call `AddAuthorized`:

```csharp
using Pug.Authorize.Data.SqlLite;
using Pug.Authorized;
using Pug.Authorized.DependencyInjection;
using System.Data.SQLite;

// Register the SQLite data store
builder.Services.AddSingleton<IApplicationData<IAuthorizedDataStore>>(
    new AuthorizationDataStore(
        "data source=authorizations.sqlite",
        SQLiteFactory.Instance
    )
);

// Register IAuthorized
builder.Services.AddAuthorized(
    new Options
    {
        AdministratorRole  = "ADMINISTRATORS",   // role name that grants admin access
        AdministrativeUser = "admin",            // user identifier that is always an admin
        ManagementDomain   = "management",       // domain reserved for admin ACEs
        AdministrativeActionGrantees = AdministrativeActionGrantees.Administrators
    },
    new DefaultIdentifierGenerator()
);
```

`AdministrativeActionGrantees` controls who may call `GetAccessControlEntriesAsync` / `SetAccessControlEntriesAsync`:

| Value | Behaviour |
|-------|-----------|
| `Administrators` | Only the admin user/role (default) |
| `AllowedUsers` | Any subject that has been granted `MANAGE_ACCESS_CONTROL_ENTRIES` |
| `Subject` | The subject whose entries are being queried may read their own |

### 3. Grant permissions

Use `SetAccessControlListsAsync` to define permissions for multiple subjects at once, or `SetAccessControlEntriesAsync` for a single subject.

The calling user must be an administrator (or have `MANAGE_ACCESS_CONTROL_ENTRIES` permission when `AdministrativeActionGrantees.AllowedUsers` is configured).

```csharp
// IAuthorized injected via DI
await authorized.SetAccessControlListsAsync(
    purpose: "documents",
    @object: new NounQualifier { Domain = "acme", Type = "DOCUMENT", Identifier = "report-q1" },
    accessControlLists: new Dictionary<Noun, IEnumerable<AccessControlEntryDefinition>>
    {
        // Give alice READ on this specific document
        [new Noun { Type = SubjectTypes.User, Identifier = "alice" }] = new[]
        {
            new AccessControlEntryDefinition
            {
                Action      = "READ",
                Permissions = Permissions.Allowed,
                Context     = Array.Empty<AccessControlContextEntry>()
            }
        },
        // Allow the "editors" group to modify any document in the tenant
        [new Noun { Type = SubjectTypes.Group, Identifier = "editors" }] = new[]
        {
            new AccessControlEntryDefinition
            {
                Action      = "MODIFY",
                Permissions = Permissions.Allowed,
                Context     = Array.Empty<AccessControlContextEntry>()
            },
            new AccessControlEntryDefinition
            {
                Action      = "DELETE",
                Permissions = Permissions.Denied,
                Context     = Array.Empty<AccessControlContextEntry>()
            }
        }
    }
);
```

To grant permissions for an entire object **type** rather than a specific instance, set `Identifier` to an empty string:

```csharp
// Applies to all DOCUMENT objects in domain "acme"
new NounQualifier { Domain = "acme", Type = "DOCUMENT", Identifier = string.Empty }
```

### 4. Check authorization

```csharp
Permissions result = await authorized.IsAuthorizedAsync(
    subject: new Noun { Type = SubjectTypes.User, Identifier = "alice" },
    action:  "READ",
    @object: new NounQualifier { Domain = "acme", Type = "DOCUMENT", Identifier = "report-q1" },
    context: new Dictionary<string, IEnumerable<string>>(),
    purpose: "documents"
);

if (result == Permissions.Allowed)
{
    // serve the document
}
```

The framework resolves permissions for `alice` directly, then accumulates permissions from any roles/groups `alice` belongs to (via `IPrincipalRoleProvider`). An explicit `Denied` on any entry short-circuits to `Permissions.Denied`.

### 5. Contextual (attribute-based) permissions

Attach runtime conditions to an ACE. The entry only applies when every condition matches the context passed at check time:

```csharp
// Only allow approval when the document is in "pending" state
new AccessControlEntryDefinition
{
    Action      = "APPROVE",
    Permissions = Permissions.Allowed,
    Context     = new[]
    {
        new AccessControlContextEntry
        {
            Key       = "status",
            MatchType = AccessControlContextMatchType.Equals,
            Values    = new[] { "pending" }
        }
    }
}
```

Pass the runtime state as context when checking:

```csharp
await authorized.IsAuthorizedAsync(
    subject,
    "APPROVE",
    @object,
    context: new Dictionary<string, IEnumerable<string>>
    {
        ["status"] = new[] { document.Status }
    },
    purpose: "documents"
);
```

### 6. Read access control entries

Retrieve all ACEs for an object/subject pair (subject to `AdministrativeActionGrantees` policy):

```csharp
IEnumerable<AccessControlEntry> entries = await authorized.GetAccessControlEntriesAsync(
    purpose: "documents",
    @object: new NounQualifier { Domain = "acme", Type = "DOCUMENT", Identifier = "report-q1" },
    subject: new Noun { Type = SubjectTypes.User, Identifier = "alice" }
);
```

Or retrieve the full ACL for an object (all subjects):

```csharp
IDictionary<Noun, IEnumerable<AccessControlEntry>> acl = await authorized.GetAccessControlListsAsync(
    purpose: "documents",
    @object: new NounQualifier { Domain = "acme", Type = "DOCUMENT", Identifier = "report-q1" }
);
```

## REST API

Register the `WebApiHandler` and map the built-in Minimal API endpoints to expose ACL management over HTTP:

```csharp
// Program.cs
builder.Services.AddSingleton<WebApiHandler>();

var app = builder.Build();
app.MapAuthorizationApis(basePath: "/authorizations");
```

The following endpoints are registered (all require authentication):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/authorizations/objects/{domain}/{objectType}/{objectIdentifier}/effectivePermission` | Check effective permission for a subject/action |
| `GET` | `/authorizations/objects/{domain}/{objectType}/{objectIdentifier}/accessControlLists` | Retrieve full ACL for an object |
| `GET` | `/authorizations/objects/{domain}/{objectType}/{objectIdentifier}/accessControlLists/subjects/{subjectType}/{subjectIdentifier}` | Retrieve ACEs for one subject |
| `POST` | `/authorizations/objects/{domain}/{objectType}/{objectIdentifier}/accessControlLists/subjects/{subjectType}/{subjectIdentifier}` | Set ACEs for one subject |
| `POST` | `/authorizations/objects/{domain}/{objectType}/{objectIdentifier}/accessControlLists/` | Set ACL for multiple subjects |

Pass `purpose` as an HTTP header on all requests.

## Related

- [Pug.Groups](https://github.com/NDWX/Pug.Groups) — Multi-tenant group membership framework; uses Pug.Authorize to control access to group management operations
