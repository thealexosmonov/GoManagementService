#GoManagementService

##Background:

The following package is zipped & deployed to an AWS lambda, which backs the GoManagementService.

Currently, the following APIs are supported:

* /ping - sanity check
* /reset - resets entire environment and auto-generates new mock data
* /user/update - create/updates user
* /user/signin - signs in user & returns corresponding role 
* /truck/update - creates/updates truck
* /trucks/search - searches for available trucks based on parameters
* /reservations/list - lists all reservations for a user
* /reservations/book - creates a new reservation for a user


##Useful Commands:

To "build" (zip) the package, simply run the following command:

```zip go_management_service.zip handler.py```

This will grab the handler.py and zip it under './go_management_service.zip'