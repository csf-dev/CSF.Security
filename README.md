# CSF.Security
This library provides an abstraction to logging into an application using a password.
It encapsulates a number of best-practices into a central service type which may be consumed and extended by your own application.

## Documentation
The best place for documentation is [the project wiki on GitHub].  Internally this library primarily supports **PBKDF2** password hashing, via the built-in [Rfc2898DeriveBytes] type.  However, it may be easily extended with any other password-verification algorithms.

[the project wiki on GitHub]: https://github.com/csf-dev/CSF.Security/wiki
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