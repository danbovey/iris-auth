# iris-auth

[Iris Framework](https://github.com/kataras/iris) middleware for HTTP basic authentication. Supports checking logins against bcrypt hashed passwords.

## Usage

```go
import (
    "github.com/kataras/iris"
	"github.com/kataras/iris/context"
    authenticator "github.com/danbovey/iris-auth"
)

func main() {
    app := iris.Default()

    username := // Get username from database
	password := // Get password from database
	authMiddleware := authenticator.New(authenticator.NewSimpleBasic(username, password))

    routes := app.Party("/", authMiddleware)
    {
		routes.Get("/", func(ctx context.Context) {
			ctx.writeString("Hello world")
		})
	}
}
```

## Authors

* [Dan Bovey](https://github.com/danbovey)
* [Jeremy Saenz](http://github.com/codegangsta)
* [Brendon Murphy](http://github.com/bemurphy)
* [nabeken](https://github.com/nabeken)
