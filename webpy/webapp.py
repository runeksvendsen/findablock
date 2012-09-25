import web, json
import createblock

urls = ('/', 'index', '/request', 'request')
render = web.template.render('templates/')

app = web.application(urls, globals())

class index:
   def GET(self):
      return render.index()

class request:
   def POST(self):
      return self.handle_request(web.data())

   def handle_request(self, data):
      response = self.convert_response(data)
      if response['request'] == "getblock":
         web.header('Content-Type', 'application/json')
         return str(json.dumps(createblock.get_block(response['address'])))
      else:
         return "Unknown command"

   def convert_response(self, data):
      dict = {}
      for pair in data.split('&'):
         dict[pair.split('=')[0]] = pair.split('=')[1]
      return dict

if __name__ == '__main__':
   app.run()

