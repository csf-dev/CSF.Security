# CSF.Security
This library provides types related to authentication, authorisation and application security.
Presently, the only functionality on offer is `IAuthenticationService<T>` and its default generic implementation.

The only implementation of `ICredentialVerifier` provided uses the PBKDF2 algorithm, which is designed for password hashing.
Behind the scenes, this uses the .NET framework built-in [Rfc2898DeriveBytes] type.
Consumers should:

* Write their own credentials implementations, representing entered and stored versions.
* Write their own repository implementation, to get stored credentials.

[Rfc2898DeriveBytes]: https://msdn.microsoft.com/en-gb/library/system.security.cryptography.rfc2898derivebytes(v=vs.110).aspx

## Open source license
All source files within this project are released as open source software,
under the terms of [the MIT license].

[the MIT license]: http://opensource.org/licenses/MIT

This software is distributed in the hope that it will be useful, but please
remember that:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.