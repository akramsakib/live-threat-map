FROM python:3.12-slim

WORKDIR /app
COPY . .

# No pip install needed - stdlib only.
ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python3 -c "import urllib.request,os,sys; \
      sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/healthz',timeout=4).status==200 else 1)"

CMD ["python3", "server.py"]
