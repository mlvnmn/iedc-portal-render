# IEDC Event Portal

This is a Flask web application for managing event submissions for the IEDC (Innovation and Entrepreneurship Development Cell).

## Features

- **User Roles:** Admin, Teacher, and Student.
- **Department-based access control:** Students can submit event photos and descriptions, which can only be approved by teachers from the same department.
- **Admin Dashboard:** Admins can view all approved submissions and download them as a zip file.
- **File Storage:** Images are uploaded to Cloudinary.

## Deployment

This application can be deployed using a Gunicorn server. The `Procfile` in the root directory is configured to run the application with Gunicorn.

```bash
gunicorn app:app
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss any changes.

## License

MIT License

Copyright (c) 2023 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

