import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Plus, Check, X, Rocket, Star, Edit, Save } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { UserProfile } from '@/components/auth/UserProfile';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/api';

export const TodoApp = () => {
  const [todos, setTodos] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [editingText, setEditingText] = useState('');
  const { toast } = useToast();
  const { user } = useAuth();

  const addTodo = () => {
    if (inputValue.trim()) {
      const newTodo = {
        id: Date.now().toString(),
        text: inputValue.trim(),
        completed: false,
        createdAt: new Date(),
      };
      setTodos([...todos, newTodo]);
      setInputValue('');
      toast({
        title: "Mission Added!",
        description: `New cosmic task: "${newTodo.text}"`,
      });
    }
  };

  const toggleTodo = (id) => {
    setTodos(todos.map(todo => 
      todo.id === id ? { ...todo, completed: !todo.completed } : todo
    ));
  };

  const deleteTodo = (id) => {
    const todoToDelete = todos.find(t => t.id === id);
    setTodos(todos.filter(todo => todo.id !== id));
    if (todoToDelete) {
      toast({
        title: "Mission Terminated",
        description: `Removed: "${todoToDelete.text}"`,
        variant: "destructive",
      });
    }
  };

  const startEditing = (todo) => {
    setEditingId(todo.id);
    setEditingText(todo.text);
  };

  const saveEdit = async (id) => {
    if (editingText.trim() && editingText.trim() !== todos.find(t => t.id === id)?.text) {
      try {
        await api.updateTodo(id, editingText.trim());
        setTodos(todos.map(todo => 
          todo.id === id ? { ...todo, text: editingText.trim() } : todo
        ));
        toast({
          title: "Mission Updated!",
          description: `Updated: "${editingText.trim()}"`,
        });
      } catch (error) {
        toast({
          title: "Update Failed",
          description: error.message,
          variant: "destructive",
        });
      }
    }
    setEditingId(null);
    setEditingText('');
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditingText('');
  };

  const completedCount = todos.filter(todo => todo.completed).length;
  const totalCount = todos.length;

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-8">
      {/* User Profile */}
      <UserProfile />
      
      {/* Header */}
      <div className="text-center space-y-4">
        <div className="flex items-center justify-center gap-3">
          <Rocket className="w-8 h-8 text-accent animate-float" />
          <h1 className="text-4xl font-bold nebula-text">
            Cosmic Quest
          </h1>
          <Star className="w-8 h-8 text-primary animate-twinkle" />
        </div>
        <p className="text-muted-foreground text-lg">
          Welcome back, Commander {user?.name}! Navigate your missions through the stellar void
        </p>
        {totalCount > 0 && (
          <Badge variant="secondary" className="px-4 py-2 text-sm">
            {completedCount} of {totalCount} missions completed
          </Badge>
        )}
      </div>

      {/* Add Todo Form */}
      <Card className="cosmic-card p-6">
        <div className="flex gap-3">
          <Input
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Enter your next cosmic mission..."
            className="flex-1 bg-input border-border text-foreground placeholder:text-muted-foreground"
            onKeyPress={(e) => e.key === 'Enter' && addTodo()}
          />
          <Button 
            onClick={addTodo}
            className="stellar-button px-6"
            disabled={!inputValue.trim()}
          >
            <Plus className="w-5 h-5" />
            Launch
          </Button>
        </div>
      </Card>

      {/* Todos List */}
      <div className="space-y-3">
        {todos.length === 0 ? (
          <Card className="cosmic-card p-8 text-center">
            <div className="space-y-3">
              <Star className="w-12 h-12 text-muted-foreground mx-auto animate-twinkle" />
              <p className="text-muted-foreground text-lg">
                No cosmic missions yet
              </p>
              <p className="text-sm text-muted-foreground">
                Add your first task to begin your stellar journey
              </p>
            </div>
          </Card>
        ) : (
          todos.map((todo) => (
            <Card
              key={todo.id}
              className={`cosmic-card p-4 transition-all duration-300 hover:animate-glow-pulse ${todo.completed ? 'opacity-75' : ''}`}
            >
              <div className="flex items-center gap-4">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toggleTodo(todo.id)}
                  className={`w-8 h-8 rounded-full border-2 flex items-center justify-center transition-all ${
                    todo.completed
                      ? 'bg-primary border-primary text-primary-foreground'
                      : 'border-border hover:border-primary'
                  }`}
                >
                  {todo.completed && <Check className="w-4 h-4" />}
                </Button>
                
                <div className="flex-1">
                  {editingId === todo.id ? (
                    <div className="space-y-2">
                      <Input
                        value={editingText}
                        onChange={(e) => setEditingText(e.target.value)}
                        className="bg-input border-border text-foreground"
                        onKeyPress={(e) => e.key === 'Enter' && saveEdit(todo.id)}
                        onKeyDown={(e) => e.key === 'Escape' && cancelEdit()}
                        autoFocus
                      />
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => saveEdit(todo.id)}
                          className="h-6 px-2 text-xs text-primary hover:text-primary"
                        >
                          <Save className="w-3 h-3 mr-1" />
                          Save
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={cancelEdit}
                          className="h-6 px-2 text-xs text-muted-foreground hover:text-foreground"
                        >
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <p className={`transition-all ${todo.completed ? 'line-through text-muted-foreground' : 'text-foreground'}`}>
                        {todo.text}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Mission created: {todo.createdAt.toLocaleDateString()}
                      </p>
                    </>
                  )}
                </div>

                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => startEditing(todo)}
                  className="w-8 h-8 text-muted-foreground hover:text-primary hover:bg-primary/10 flex items-center justify-center"
                  disabled={editingId !== null}
                >
                  <Edit className="w-4 h-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => deleteTodo(todo.id)}
                  className="w-8 h-8 text-destructive hover:text-destructive hover:bg-destructive/10 flex items-center justify-center"
                  disabled={editingId !== null}
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            </Card>
          ))
        )}
      </div>

      {/* Progress Summary */}
      {totalCount > 0 && (
        <Card className="cosmic-card p-6 text-center">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">Mission Progress</p>
            <div className="w-full bg-muted rounded-full h-2">
              <div
                className="bg-primary h-2 rounded-full transition-all duration-500"
                style={{ width: `${(completedCount / totalCount) * 100}%` }}
              />
            </div>
            <p className="text-sm font-medium">
              {Math.round((completedCount / totalCount) * 100)}% Complete
            </p>
          </div>
        </Card>
      )}
    </div>
  );
};
